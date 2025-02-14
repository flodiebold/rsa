
use std::{error::Error, io::{Read, stdin, stdout, Write}};
use num_bigint::{BigInt, BigUint, Sign};
use serde::{Deserialize, Serialize};
use num_integer::Integer;
use rand::Rng;

mod bleichenbacher;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    e: BigUint,
    n: BigUint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey {
    d: BigUint,
}

fn modular_inverse(x: BigUint, m: BigUint) -> BigUint {
    let m = BigInt::from_biguint(Sign::Plus, m);
    let e = BigInt::from_biguint(Sign::Plus, x).extended_gcd(&m);
    e.x.to_biguint().or((m + e.x).to_biguint()).unwrap()
}

fn pkcs_pad(mut message: Vec<u8>, size: usize) -> Vec<u8> {
    message.insert(0, 0);
    for _ in 0..(size-2-message.len()) {
        let mut b = rand::thread_rng().gen();
        if b == 0 { b = 1; }
        message.insert(0, b);
    }
    message.insert(0, 2);
    // last byte 0 doesn't matter
    message
}

fn pkcs_unpad(mut message: Vec<u8>, size: usize) -> Result<Vec<u8>, ()> {
    if message[0] != 2 || message.len() != size - 1 {
        return Err(());
    }
    let padding_len = message.iter().enumerate().filter(|(_, b)| **b == 0).next()
        .ok_or(())?.0 + 1;
    message.drain(0..padding_len);
    Ok(message)
}

fn rsa_keygen() -> (PublicKey, PrivateKey) {
    loop {
        let p = glass_pumpkin::prime::new(512).unwrap();
        let q = glass_pumpkin::prime::new(512).unwrap();
        let n = &p * &q;
        let phi = (p - 1u32) * (q - 1u32);
        let e = BigUint::from(3u32);
        if e.gcd(&phi) != 1u32.into() {
            continue;
        }
        let d = modular_inverse(e.clone(), phi);
        let public_key = PublicKey { e, n };
        let private_key = PrivateKey { d };
        return (public_key, private_key);
    }
}

fn rsa_encrypt(message: &[u8], key: PublicKey) -> Vec<u8> {
    let key_size = key.n.bits().div_ceil(&8);
    let message = pkcs_pad(message.to_owned(), key_size);
    let message = BigUint::from_bytes_be(&message);

    if message >= key.n {
        panic!("message is too large!");
    }

    let encrypted = message.modpow(&key.e, &key.n);

    let data = encrypted.to_bytes_be();

    data
}

fn rsa_decrypt(message: &[u8], (public_key, private_key): &(PublicKey, PrivateKey)) -> Result<Vec<u8>, ()> {
    let key_size = public_key.n.bits().div_ceil(&8);
    let message = BigUint::from_bytes_be(&message);

    if message >= public_key.n {
        panic!("message is too large!");
    }

    let encrypted = message.modpow(&private_key.d, &public_key.n);

    let data = encrypted.to_bytes_be();

    pkcs_unpad(data, key_size)
}

fn crack_1(message: &[u8], _public_key: PublicKey) -> Vec<u8> {
    let message = BigUint::from_bytes_be(&message);

    let decrypted = message.nth_root(3);

    let data = decrypted.to_bytes_be();

    data
}

fn save_key(key_pair: (PublicKey, PrivateKey)) -> Result<(), Box<dyn Error>> {
    let file = std::fs::File::create("./private_key.json")?;
    serde_json::to_writer(file, &key_pair.1)?;
    let file = std::fs::File::create("./public_key.json")?;
    serde_json::to_writer(file, &key_pair.0)?;
    Ok(())
}

fn load_key() -> Result<(PublicKey, PrivateKey), Box<dyn Error>> {
    let file = std::fs::File::open("./private_key.json")?;
    let private_key = serde_json::from_reader(file)?;
    let file = std::fs::File::open("./public_key.json")?;
    let public_key = serde_json::from_reader(file)?;
    Ok((public_key, private_key))
}

fn load_public_key() -> Result<PublicKey, Box<dyn Error>> {
    let file = std::fs::File::open("./public_key.json")?;
    let public_key = serde_json::from_reader(file)?;
    Ok(public_key)
}

fn main() -> Result<(), Box<dyn Error>> {
    match std::env::args().skip(1).next() {
        Some(s) if &s == "keygen" => {
            eprintln!("Generating highly secure key...");
            let key_pair = rsa_keygen();
            save_key(key_pair)?;
        }
        Some(s) if &s == "encrypt" || &s == "decrypt" => {
            let mut data = Vec::new();

            stdin().lock().read_to_end(&mut data)?;

            let result = if s == "encrypt" {
                let key = load_public_key()?;
                rsa_encrypt(&data, key)
            } else {
                let key_pair = load_key()?;

                rsa_decrypt(&data, &key_pair).map_err(|_| "Invalid PKCS padding")?
            };

            stdout().lock().write_all(&result)?;
        }
        Some(s) if &s == "crack_1" => {
            let mut data = Vec::new();

            stdin().lock().read_to_end(&mut data)?;

            let key = load_public_key()?;
            let result = crack_1(&data, key);

            stdout().lock().write_all(&result)?;
        }
        Some(s) if &s == "bleichenbacher" => {
            let mut data = Vec::new();

            stdin().lock().read_to_end(&mut data)?;

            let key = load_key()?;
            let oracle = |msg: Vec<u8>| {
                let result = rsa_decrypt(&msg, &key);

                result.is_ok()
            };

            let result = bleichenbacher::bleichenbacher(&data, &key.0, &oracle);

            stdout().lock().write_all(&result)?;
        }
        _ => {
            eprintln!("Please specify one of keygen, encrypt or decrypt.");
            std::process::exit(1);
        }
    }

    Ok(())
}
