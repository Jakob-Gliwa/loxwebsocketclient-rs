//! Optional persistence for the session token.
//!
//! Without a store the client acquires a fresh token on every process start,
//! which costs a `getkey2` + `getjwt` round trip and needs the password. A
//! store lets a restart re-use the token it already had — see [`TokenStore`]
//! for what that does and does not buy you.

use crate::auth::LxToken;
use crate::crypto::HashAlg;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Somewhere to keep the token across process restarts.
///
/// # What this is for
///
/// Surviving a crash, a `SIGKILL` or a container restart. A *graceful*
/// [`LoxClient::stop`] sends `killtoken` by default, which makes the saved
/// token worthless on purpose; set [`ConnectConfig::kill_token_on_stop`] to
/// `false` if a clean restart should re-use it too.
///
/// # Contract
///
/// `binding` identifies the Miniserver, user and client UUID the token was
/// issued for. An implementation must never hand back a token saved under a
/// different binding: a token belongs to one account, and handing the wrong one
/// out is an authorisation bug, not a cache miss.
///
/// All three methods are called from the client's IO task and must not block
/// for long. They cannot fail the connection — an implementation reports
/// trouble by logging and, for [`load`](Self::load), returning `None`. Losing a
/// saved token only costs a fresh handshake.
///
/// Implementations hold bearer material equivalent to the user's password, so
/// keep the `Debug` output free of it and the storage readable only by the
/// account running the client.
///
/// [`LoxClient::stop`]: crate::LoxClient::stop
/// [`ConnectConfig::kill_token_on_stop`]: crate::ConnectConfig::kill_token_on_stop
pub trait TokenStore: Send + Sync + fmt::Debug {
    /// The token saved for `binding`, or `None` when there is none to re-use.
    fn load(&self, binding: &str) -> Option<LxToken>;

    /// Save `token` for `binding`, replacing whatever was there.
    fn save(&self, binding: &str, token: &LxToken);

    /// Forget the token for `binding`; it has been invalidated.
    fn clear(&self, binding: &str);
}

/// Key tying a token to the identity it was issued for.
///
/// Hashed so that neither the URL nor the user name ends up in a file that may
/// be more widely readable than intended, and so the value is a fixed-size
/// string an implementation can safely use as a filename or keyring entry.
///
/// The URL is used as configured rather than normalised: spelling the same
/// Miniserver two ways costs a fresh token, which is harmless, whereas guessing
/// at equivalence could hand a token to the wrong host.
pub(crate) fn token_binding(loxone_url: &str, username: &str, client_uuid: &str) -> String {
    let mut hasher = Sha256::new();
    // Length-prefixed so that ("ab", "c") and ("a", "bc") cannot collide.
    for part in [loxone_url, username, client_uuid] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

const MAGIC: &str = "loxwebsocket-token 1";

/// Keeps one token in one file, readable only by the account that wrote it.
///
/// The file is replaced atomically (write to a sibling temporary, then rename),
/// so an interrupted save leaves the previous token intact rather than a
/// half-written one. On Unix the file is created with mode `0600` and any
/// missing parent directories with `0700`; other platforms get whatever the
/// default permissions are, which is why this type is a reasonable default but
/// not the last word — a keyring-backed [`TokenStore`] is stronger.
///
/// # Example
///
/// ```no_run
/// use loxwebsocket::{ConnectConfig, FileTokenStore};
/// use std::sync::Arc;
///
/// let cfg = ConnectConfig {
///     // A graceful stop kills the token by default, which would leave the
///     // store holding something already dead.
///     kill_token_on_stop: false,
///     ..ConnectConfig::new("http://192.168.1.5", "user", "pass")
/// }
/// .with_token_store(Arc::new(FileTokenStore::new("/var/lib/myapp/lox_token.cfg")));
/// ```
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    path: PathBuf,
}

impl FileTokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_record(&self) -> Option<(String, LxToken)> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                warn!(path = %self.path.display(), "token file unreadable: {e}");
                return None;
            }
        };
        warn_if_widely_readable(&self.path);

        let mut lines = raw.lines();
        if lines.next() != Some(MAGIC) {
            warn!(path = %self.path.display(), "token file is not in a format this version writes");
            return None;
        }

        let (mut binding, mut token, mut valid_until, mut hash_alg) = (None, None, None, None);
        for line in lines {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            // First occurrence wins. A later line must never be able to
            // override the binding an earlier one established.
            match key {
                "binding" if binding.is_none() => binding = Some(value.to_string()),
                "token" if token.is_none() => token = Some(value.to_string()),
                "valid_until" if valid_until.is_none() => valid_until = value.parse::<i64>().ok(),
                "hash_alg" if hash_alg.is_none() => hash_alg = HashAlg::parse(value).ok(),
                _ => {}
            }
        }

        match (binding, token, valid_until, hash_alg) {
            (Some(binding), Some(token), Some(valid_until), Some(hash_alg))
                if !token.is_empty() =>
            {
                Some((binding, LxToken::new(token, valid_until, hash_alg)))
            }
            _ => {
                warn!(path = %self.path.display(), "token file is incomplete, ignoring it");
                None
            }
        }
    }

    fn write_record(&self, binding: &str, token: &LxToken) -> std::io::Result<()> {
        // The format is line-based, so a newline inside a value would let the
        // Miniserver's answer forge further fields — a `binding` of its
        // choosing above all, which is what keeps its token off other accounts.
        // A JWT cannot contain one, so refusing is free.
        if token.token.contains(['\n', '\r']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the token contains a line break",
            ));
        }

        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_private_dir(parent)?;
        }

        // A sibling rather than a temp dir, so the rename below stays on one
        // filesystem and is therefore atomic.
        let tmp = self.path.with_extension("tmp");
        // A leftover from an interrupted save would keep its old permissions,
        // because `mode` only applies to a file this call creates.
        let _ = fs::remove_file(&tmp);

        let record = format!(
            "{MAGIC}\nbinding={binding}\nhash_alg={}\nvalid_until={}\ntoken={}\n",
            token.hash_alg.as_str(),
            token.valid_until,
            token.token,
        );

        let mut file = create_private_file(&tmp)?;
        file.write_all(record.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp, &self.path)
    }
}

impl TokenStore for FileTokenStore {
    fn load(&self, binding: &str) -> Option<LxToken> {
        let (saved_binding, token) = self.read_record()?;
        if saved_binding != binding {
            debug!(
                path = %self.path.display(),
                "saved token belongs to a different Miniserver, user or client uuid"
            );
            return None;
        }
        Some(token)
    }

    fn save(&self, binding: &str, token: &LxToken) {
        if token.is_empty() {
            self.clear(binding);
            return;
        }
        if let Err(e) = self.write_record(binding, token) {
            warn!(path = %self.path.display(), "could not save the token: {e}");
        }
    }

    fn clear(&self, _binding: &str) {
        match fs::remove_file(&self.path) {
            Ok(()) => debug!(path = %self.path.display(), "saved token discarded"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(path = %self.path.display(), "could not discard the token: {e}"),
        }
    }
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::File::create(path)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn warn_if_widely_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = fs::metadata(path) else { return };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        warn!(
            path = %path.display(),
            "token file is readable beyond its owner (mode {mode:04o}); it holds bearer credentials"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_widely_readable(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that removes itself, so the tests need no dev-dependency.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "loxwebsocket-store-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn token() -> LxToken {
        LxToken::new("eyJhbGciOiJIUzI1NiJ9.payload", 1_234_567, HashAlg::Sha256)
    }

    #[test]
    fn a_saved_token_comes_back_unchanged() {
        let dir = TempDir::new("roundtrip");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        assert!(store.load("binding-a").is_none(), "nothing saved yet");

        store.save("binding-a", &token());
        let loaded = store.load("binding-a").expect("the saved token");

        assert_eq!(loaded.token, token().token);
        assert_eq!(loaded.valid_until, token().valid_until);
        assert_eq!(loaded.hash_alg, HashAlg::Sha256);
    }

    #[test]
    fn a_token_is_not_handed_to_a_different_identity() {
        let dir = TempDir::new("binding");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        store.save("binding-a", &token());

        assert!(
            store.load("binding-b").is_none(),
            "a token issued for one account must not be reused for another"
        );
        assert!(store.load("binding-a").is_some());
    }

    #[test]
    fn the_binding_separates_url_user_and_client() {
        let base = token_binding("http://ms.local", "admin", "uuid");
        assert_eq!(base, token_binding("http://ms.local", "admin", "uuid"));
        assert_ne!(base, token_binding("http://other.local", "admin", "uuid"));
        assert_ne!(base, token_binding("http://ms.local", "guest", "uuid"));
        assert_ne!(base, token_binding("http://ms.local", "admin", "other"));
        // Field boundaries are unambiguous: no regrouping produces a collision.
        assert_ne!(token_binding("ab", "c", "d"), token_binding("a", "bc", "d"));
    }

    #[test]
    fn clearing_removes_the_file() {
        let dir = TempDir::new("clear");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        store.save("binding-a", &token());
        assert!(store.path().exists());

        store.clear("binding-a");
        assert!(!store.path().exists());
        assert!(store.load("binding-a").is_none());
        // Clearing what is already gone is not an error.
        store.clear("binding-a");
    }

    #[test]
    fn saving_an_empty_token_clears_instead_of_writing_one() {
        let dir = TempDir::new("empty");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        store.save("binding-a", &token());

        store.save("binding-a", &LxToken::default());
        assert!(!store.path().exists());
    }

    #[test]
    fn a_damaged_file_is_ignored_rather_than_half_read() {
        let dir = TempDir::new("damaged");
        let store = FileTokenStore::new(dir.file("token.cfg"));

        fs::write(store.path(), "not a token file at all\n").unwrap();
        assert!(store.load("binding-a").is_none());

        fs::write(store.path(), format!("{MAGIC}\nbinding=binding-a\n")).unwrap();
        assert!(store.load("binding-a").is_none(), "no token field");

        // And it recovers: a save over the damaged file works.
        store.save("binding-a", &token());
        assert!(store.load("binding-a").is_some());
    }

    #[test]
    fn a_token_cannot_forge_extra_fields() {
        let dir = TempDir::new("injection");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        store.save("binding-a", &token());

        // A token carrying a line break could otherwise append a `binding` line
        // of its own and get itself served to a different account.
        let forged = LxToken::new("evil\nbinding=binding-b", 1_234_567, HashAlg::Sha256);
        store.save("binding-a", &forged);

        assert_eq!(
            store.load("binding-a").expect("the earlier token").token,
            token().token,
            "the forged token must not have replaced the good one"
        );
        assert!(store.load("binding-b").is_none());
    }

    #[test]
    fn a_repeated_field_does_not_override_the_first() {
        let dir = TempDir::new("duplicate");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        fs::write(
            store.path(),
            format!("{MAGIC}\nbinding=binding-a\nhash_alg=SHA256\nvalid_until=1\ntoken=t\nbinding=binding-b\n"),
        )
        .unwrap();

        assert!(store.load("binding-a").is_some());
        assert!(store.load("binding-b").is_none());
    }

    #[test]
    fn missing_parent_directories_are_created() {
        let dir = TempDir::new("nested");
        let store = FileTokenStore::new(dir.file("a/b/token.cfg"));

        store.save("binding-a", &token());
        assert!(store.load("binding-a").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("perms");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        store.save("binding-a", &token());

        let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the token is bearer material");
    }

    #[cfg(unix)]
    #[test]
    fn a_save_over_a_leftover_temporary_still_ends_up_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("leftover");
        let store = FileTokenStore::new(dir.file("token.cfg"));

        // What an interrupted save leaves behind, with permissions to match.
        let tmp = store.path().with_extension("tmp");
        fs::write(&tmp, "stale").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();

        store.save("binding-a", &token());

        let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!tmp.exists(), "the temporary was renamed, not left behind");
    }

    #[test]
    fn debug_output_keeps_the_token_out_of_it() {
        let dir = TempDir::new("debug");
        let store = FileTokenStore::new(dir.file("token.cfg"));
        assert!(!format!("{store:?}").contains("payload"));
        assert!(!format!("{:?}", token()).contains("payload"));
    }
}
