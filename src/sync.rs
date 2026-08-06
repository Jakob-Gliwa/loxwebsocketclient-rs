//! Poison-tolerant locking.
//!
//! Every mutex in this crate guards plain bookkeeping data, never an invariant
//! that a panicking task could leave half-updated. Propagating poisoning would
//! therefore turn one unrelated panic into a permanently dead client, so the
//! guard is recovered instead.

use std::sync::{Mutex, MutexGuard};

/// Lock `mutex`, recovering the guard if a previous holder panicked.
#[inline]
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn recovers_from_poisoning() {
        let m = Arc::new(Mutex::new(7));
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap();
            panic!("poison it");
        })
        .join();
        assert!(m.lock().is_err());
        assert_eq!(*lock(&m), 7);
    }
}
