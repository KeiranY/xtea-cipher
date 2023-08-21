use std::io;

use buffed_io::{bytes::Bytes, Buffered};

#[derive(Debug)]
pub struct Xtea {
    key: Vec<u32>,
    rounds: u32,
}

const DEFAULT_ROUNDS: u32 = 32;

const DELTA: u32 = 0x9E3779B9;

impl Xtea {
    pub fn new(key: Vec<u32>) -> Self {
        assert!(key.len() == 4);
        Self {
            key,
            rounds: DEFAULT_ROUNDS,
        }
    }

    pub fn encipher(
        &self,
        input: &mut Buffered<Bytes>,
        output: &mut Buffered<Bytes>,
    ) -> io::Result<()> {
        self.do_cipher(input, output, true)
    }

    pub fn decipher(
        &self,
        input: &mut Buffered<Bytes>,
        output: &mut Buffered<Bytes>,
    ) -> io::Result<()> {
        self.do_cipher(input, output, false)
    }

    fn encipher_block(&self, input: &[u32; 2], output: &mut [u32; 2]) {
        let mut v0 = input[0];
        let mut v1 = input[1];
        let mut sum = 0u32;

        for _ in 0..self.rounds {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + self.key[(sum & 3) as usize]);
            sum += DELTA;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + self.key[((sum >> 11) & 3) as usize]);
        }

        output[0] = v0;
        output[1] = v1;
    }

    fn decipher_block(&self, input: &[u32; 2], output: &mut [u32; 2]) {
        let mut v0 = input[0];
        let mut v1 = input[1];
        let mut sum = DELTA * self.rounds;

        for _ in 0..self.rounds {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + self.key[((sum >> 11) & 3) as usize]);
            sum -= DELTA;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + self.key[(sum & 3) as usize]);
        }

        output[0] = v0;
        output[1] = v1;
    }

    fn do_cipher(
        &self,
        input: &mut Buffered<Bytes>,
        output: &mut Buffered<Bytes>,
        decipher: bool,
    ) -> io::Result<()> {
        let mut input_buf = [0_u32; 2];
        let mut output_buf = [0_u32; 2];
        let iterations = input.remaining() / 8;
        for _ in 0..=iterations {
            input_buf[0] = input.get_u32()?;
            input_buf[1] = input.get_u32()?;

            if decipher {
                self.decipher_block(&input_buf, &mut output_buf);
            } else {
                self.encipher_block(&input_buf, &mut output_buf);
            }

            output.put_u32(output_buf[0]);
            output.put_u32(output_buf[1]);
        }
        Ok(())
    }
}
