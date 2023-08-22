# XTEA Block (De)cipher

<p align="center"><i>A minimal, zero-dependency XTEA block (de)cipher utility.</i></p>

## Usage

Currently, there are only two direct means of working with this crate in its current state. 

A basic, minimal example for encrypting some arbitrary data could be achieved by the following:
```rust
/// Construct the block cipher accordingly to fit the use-case.
let xtea_cipher = Xtea::using_key([0u32, 0u32, 0u32, 0u32])
    // Optionally, the amount of rounds to be applied may be specified. Otherwise, the
    // suggested amount of 32 will be used.
    .with_rounds(10);

/// Create the input array to be processed as well as a suitable output array to write the processed results to.
let mut input = vec![0u8; 60];
let mut output = Vec::with_capacity(input.len());

/// Handle any error results.
if let Err(e) = xtea_cipher.encipher(&mut input, &mut output) {
        ...    
}
```

Similarly, decrypting data can be achieved by doing the following:
```rust
let xtea_cipher = Xtea::using_key([0u32, 0u32, 0u32, 0u32]);

let mut input = vec![0u8; 60];
let mut output = Vec::with_capacity(input.len());

/// Handle any error results.
if let Err(e) = xtea_cipher.decipher(&mut input, &mut output) {
    ..
}
``` 

### Note

This crate is likely to undergo breaking changes over the span of future releases until its marked as stable in version `1.0.0`. However, breaking changes will be avoided unless justified. Additionally, please feel free to create an [issue on github](https://github.com/heavens/xtea-cipher/issues) citing any bugs/unexpected behavior and or lacking support. 
