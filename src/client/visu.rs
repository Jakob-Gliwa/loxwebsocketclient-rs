//! Visualization-password secured IO queue (max 1 pending, matching Python).
//!
//! The queue is shared between the writer, which enqueues the command and asks
//! for a fresh `getvisusalt`, and the reader, which drains it once the answer
//! arrives. No key/salt is cached: the visu salt may rotate at any time and a
//! stale one produces a silently rejected command.

use std::collections::VecDeque;

/// Queued secured control awaiting a `getvisusalt` response.
#[derive(Debug, Clone)]
pub struct VisuPending {
    pub uuid: String,
    pub value: String,
    pub visu_pw: String,
}

/// Max-1 pending queue for visu-secured commands.
#[derive(Debug, Default)]
pub struct VisuQueue {
    pending: VecDeque<VisuPending>,
}

impl VisuQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue; drops the oldest if already full (capacity 1).
    pub fn push(&mut self, item: VisuPending) {
        if !self.pending.is_empty() {
            self.pending.pop_front();
        }
        self.pending.push_back(item);
    }

    pub fn drain(&mut self) -> Vec<VisuPending> {
        self.pending.drain(..).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(uuid: &str) -> VisuPending {
        VisuPending {
            uuid: uuid.into(),
            value: "on".into(),
            visu_pw: "1234".into(),
        }
    }

    #[test]
    fn newest_command_wins() {
        let mut q = VisuQueue::new();
        assert!(q.is_empty());
        q.push(item("a"));
        q.push(item("b"));
        let drained = q.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].uuid, "b");
        assert!(q.is_empty());
    }
}
