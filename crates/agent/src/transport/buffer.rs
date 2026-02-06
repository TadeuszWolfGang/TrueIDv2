//! Fixed-capacity ring buffer for offline event buffering.

use std::collections::VecDeque;

/// Ring buffer that drops the oldest entry when full.
pub struct RingBuffer {
    inner: VecDeque<Vec<u8>>,
    capacity: usize,
    dropped: u64,
}

impl RingBuffer {
    /// Creates a new ring buffer with the given capacity.
    ///
    /// Parameters: `capacity` - maximum number of entries.
    /// Returns: empty `RingBuffer`.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    /// Pushes a framed message into the buffer, dropping the oldest if full.
    ///
    /// Parameters: `data` - framed syslog bytes.
    pub fn push(&mut self, data: Vec<u8>) {
        if self.inner.len() >= self.capacity {
            self.inner.pop_front();
            self.dropped += 1;
        }
        self.inner.push_back(data);
    }

    /// Drains all buffered messages for flushing after reconnect.
    ///
    /// Parameters: none.
    /// Returns: iterator over buffered byte vectors.
    pub fn drain(&mut self) -> std::collections::vec_deque::Drain<'_, Vec<u8>> {
        self.inner.drain(..)
    }

    /// Returns the number of messages currently buffered.
    ///
    /// Parameters: none.
    /// Returns: count of buffered entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer is empty.
    ///
    /// Parameters: none.
    /// Returns: emptiness flag.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns total number of messages dropped due to overflow.
    ///
    /// Parameters: none.
    /// Returns: drop count since creation.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
