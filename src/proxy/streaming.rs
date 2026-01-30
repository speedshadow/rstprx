use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use parking_lot::Mutex;

pub struct StreamingBuffer {
    buffer: Arc<Mutex<BytesMut>>,
    chunk_size: usize,
}

impl StreamingBuffer {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(BytesMut::with_capacity(chunk_size * 2))),
            chunk_size,
        }
    }

    pub fn write(&self, data: &[u8]) {
        let mut buffer = self.buffer.lock();
        buffer.extend_from_slice(data);
    }

    pub fn read_chunk(&self) -> Option<Bytes> {
        let mut buffer = self.buffer.lock();
        if buffer.len() >= self.chunk_size {
            let chunk = buffer.split_to(self.chunk_size);
            Some(chunk.freeze())
        } else if !buffer.is_empty() {
            let chunk = buffer.split();
            Some(chunk.freeze())
        } else {
            None
        }
    }

    pub fn flush(&self) -> Option<Bytes> {
        let mut buffer = self.buffer.lock();
        if !buffer.is_empty() {
            let chunk = buffer.split();
            Some(chunk.freeze())
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_buffer() {
        let buffer = StreamingBuffer::new(10);
        
        buffer.write(b"12345");
        assert_eq!(buffer.len(), 5);
        
        buffer.write(b"67890");
        assert_eq!(buffer.len(), 10);
        
        let chunk = buffer.read_chunk();
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().len(), 10);
    }
}
