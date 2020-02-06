
use std::{error::Error, io::{Read, stdin, stdout, Write}};
use num_bigint::BigUint;

fn main() -> Result<(), Box<dyn Error>> {
    let mut data = Vec::new();

    stdin().lock().read_to_end(&mut data)?;

    let message = BigUint::from_bytes_be(&data);

    let encrypted = message;

    let data = encrypted.to_bytes_be();

    stdout().lock().write_all(&data)?;

    Ok(())
}
