use std::{cmp, io, ops::Deref};

macro_rules! impl_get_bytes {
    ($buf:ident, $byte_ty:ty, $conversion:expr) => {{
        const SIZE: usize = std::mem::size_of::<$byte_ty>();
        let limit = $buf.buffer.len();
        let pos = $buf.read_pos;
        if pos + SIZE > limit {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        let slice = unsafe { *($buf.buffer[pos..pos + SIZE].as_ptr() as *const [_; SIZE]) };
        $buf.advance_read_pos(SIZE);
        Ok($conversion(slice))
    }};
}

macro_rules! impl_put_bytes {
    ($this:tt, $value:tt) => {{
        let pos = $this.write_pos;
        let slice_len = $value.len();
        let buf_len = $this.buffer.len();
        if pos + slice_len >= buf_len {
            $this.buffer.resize(buf_len * 2, 0u8);
        }

        $this.buffer[pos..pos + slice_len].copy_from_slice($value);
        $this.advance_write_pos(slice_len);
    }};
}

pub struct Bytes {
    pub buffer: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
}

impl Bytes {

    /// Constructs a new byte buffer using the provided vector as the initial contents.
    pub fn new(contents: Vec<u8>) -> Self {
        Self {
            buffer: contents,
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Constructs a new byte buffer with the allocated capacity specified by the passed-in `capacity` value.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Constructs a new byte buffer with the allocated capacity specified by the `SIZE` type parameter. The contents of the buffer is filled with default
    /// values.
    pub fn sized<const SIZE: usize>() -> Self {
        Self {
            buffer: vec![0u8; SIZE],
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Attempts to return an unsigned byte from the reader, incrementing the position by `1` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_u8(&mut self) -> io::Result<u8> {
        impl_get_bytes!(self, u8, u8::from_be_bytes)
    }

    /// Attempts to return a signed byte from the reader, incrementing the position by `1` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_i8(&mut self) -> io::Result<i8> {
        impl_get_bytes!(self, i8, i8::from_be_bytes)
    }

    /// Attempts to return a signed short from the reader, incrementing the position by `2` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_i16(&mut self) -> io::Result<i16> {
        impl_get_bytes!(self, i16, i16::from_be_bytes)
    }

    /// Attempts to return an unsigned short from the reader, incrementing the position by `2` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_u16(&mut self) -> io::Result<u16> {
        impl_get_bytes!(self, u16, u16::from_be_bytes)
    }

    /// Attempts to return a signed integer from the reader, incrementing the position by `4` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_i32(&mut self) -> io::Result<i32> {
        impl_get_bytes!(self, i32, i32::from_be_bytes)
    }

    /// Attempts to return an unsigned integer from the reader, incrementing the position by `4` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_u32(&mut self) -> io::Result<u32> {
        impl_get_bytes!(self, u32, u32::from_be_bytes)
    }

    /// Attempts to return a signed long from the reader, incrementing the position by `8` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_i64(&mut self) -> io::Result<i64> {
        impl_get_bytes!(self, i64, i64::from_be_bytes)
    }

    /// Attempts to return an unsigned long from the reader, incrementing the position by `8` if successful. Otherwise
    /// an error is returned if not enough bytes remain.
    pub fn get_u64(&mut self) -> io::Result<u64> {
        impl_get_bytes!(self, u64, u64::from_be_bytes)
    }

    /// Writes an unsigned byte value into the buffer, incrementing the position by `1`.
    pub fn put_u8(&mut self, value: u8) {
        let slice = &u8::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    /// Writes a signed byte value into the buffer, incrementing the position by `1`.
    pub fn put_i8(&mut self, value: i8) {
        let slice = &i8::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    /// Writes a signed short value into the buffer, incrementing the position by `2`.
    pub fn put_i16(&mut self, value: i16) {
        let slice = &i16::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    /// Writes an unsigned short value into the buffer, incrementing the position by `2`.
    pub fn put_u16(&mut self, value: u16) {
        let slice: &[u8; 2] = &u16::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    /// Writes a signed int value into the buffer, incrementing the position by `4`.
    pub fn put_i32(&mut self, value: i32) {
        let slice = &i32::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    /// Writes an unsigned int value into the buffer, incrementing the position by `4`.
    pub fn put_u32(&mut self, value: u32) {
        let slice = &u32::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    /// Writes an unsigned int value into the buffer, incrementing the position by `8`.
    pub fn put_u64(&mut self, value: u64) {
        let slice = &u64::to_be_bytes(value);
        impl_put_bytes!(self, slice);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn readable(&self) -> usize {
        self.buffer.len() - self.read_pos
    }

    pub fn writable(&self) -> usize {
        self.buffer.len() - self.write_pos
    }

    pub fn advance_read_pos(&mut self, amount: usize) {
        self.read_pos += cmp::min(amount, self.readable());
    }

    pub fn advance_write_pos(&mut self, amount: usize) {
        self.write_pos += cmp::min(amount, self.writable());
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.deref()
    }
}
