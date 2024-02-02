use bytes::Bytes;
use std::io;

pub mod bytes;

/// A 128-bit key used by an [Xtea] instance when processing the block cipher.
#[derive(Clone, Debug)]
struct XteaKey(Vec<u32>);

impl std::ops::Index<usize> for XteaKey {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// An Xtea data structure equipped to perform the [eXtended TEA](https://en.wikipedia.org/wiki/XTEA) block cipher. Each XTEA
/// instance takes a 128-bit key represented in the form of [XteaKey], applying a pseudorandom permutation on passed-in data 
/// in 64-bit chunks, commonly referred to as "blocks".
#[derive(Debug)]
pub struct Xtea {
    key: XteaKey,
    rounds: u32,
}

impl Xtea {
    /// The default suggested amount of rounds to apply.
    const DEFAULT_ROUNDS: u32 = 32;

    const DELTA: u32 = 0x9E3779B9;

    /// Assigns a 128-bit key using the passed-in array of 32-bit integers.
    pub fn using_key(key: [u32; 4]) -> Self {
        assert!(key.len() == 4);
        Self {
            key: XteaKey(key.to_vec()),
            rounds: Self::DEFAULT_ROUNDS,
        }
    }

    /// Specifies the amount of rounds to be used when processing the block ciphers. This overrides the default amount of rounds
    /// used of 32.
    pub fn with_rounds(mut self, rounds: u32) -> Self {
        self.rounds = rounds;
        self
    }

    /// Encrypts the supplied `input` data and writes the processed results to the `output` array.
    pub fn encipher(&self, mut input: &[u8]) -> io::Result<Vec<u8>> {
        self.do_block_cipher(&mut input, &mut output, false)
    }

    /// Decrypts the supplied encrypted `input` array and writes the processed results to the `output` array.
    pub fn decipher(&self, input: &[u8]) -> io::Result<Vec<u8>> {
        self.do_block_cipher(input, output, true)
    }

    fn encipher_block(&self, input: &[u32; 2], output: &mut [u32; 2]) {
        let mut v0 = input[0];
        let mut v1 = input[1];
        let mut sum = 0u32;

        
        for _ in 0..self.rounds {
            v0 = v0.wrapping_add(((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ (sum.wrapping_add(self.key[(sum & 3) as usize]));
            sum = sum.wrapping_add(Self::DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ (sum.wrapping_add(self.key[((sum >> 11) & 3) as usize])),
            );
        }

        output[0] = v0;
        output[1] = v1;
    }

    fn decipher_block(&self, input: &[u32; 2], output: &mut [u32; 2]) {
        let mut v0 = input[0];
        let mut v1 = input[1];
        let mut sum = Self::DELTA.wrapping_mul(self.rounds);

        for _ in 0..self.rounds {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ (sum.wrapping_add(self.key[((sum >> 11) & 3) as usize])),
            );
            sum = sum.wrapping_sub(Self::DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ (sum.wrapping_add(self.key[(sum & 3) as usize])),
            );
        }

        output[0] = v0;
        output[1] = v1;
    }

    fn do_block_cipher(&self, input: &[u8], decrypt: bool) -> io::Result<Vec<u8>> {
        let mut input_buffer = Bytes::new(input.to_vec());
        let mut output_buffer = Bytes::new(vec![0; input.len()]);
        let mut input_slice = [0_u32; 2];
        let mut output_slice = [0_u32; 2];
        let iterations = input_buffer.readable() / 8;

        for _ in 0..iterations {
            input_slice[0] = input_buffer.get_u32()?;
            input_slice[1] = input_buffer.get_u32()?;

            if decrypt {
                self.decipher_block(&input_slice, &mut output_slice);
            } else {
                self.encipher_block(&input_slice, &mut output_slice);
            }

            output_buffer.put_u32(output_slice[0]);
            output_buffer.put_u32(output_slice[1]);
        }
        Ok(output_buffer.buffer)
    }
}
