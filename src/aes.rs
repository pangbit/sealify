use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use rand::{rngs::OsRng, seq::SliceRandom};

use crate::{Error, Result};

pub fn gen_key() -> Vec<u8> {
    Aes256Gcm::generate_key(OsRng).to_vec()
}

pub fn gen_alphanum_key() -> String {
    let mut rng = rand::thread_rng();
    String::from_utf8(
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .choose_multiple(&mut rng, 32)
            .cloned()
            .collect(),
    )
    .unwrap()
}

pub fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key: [u8; 32] = key.try_into().map_err(|_e| Error::InvalidAESKey)?;
    let key: Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| Error::AESError(e.to_string()))?;

    let mut buffer = nonce.to_vec();
    buffer.extend(ciphertext);
    Ok(buffer)
}

pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key: [u8; 32] = key.try_into().map_err(|_e| Error::InvalidAESKey)?;
    let key: Key<Aes256Gcm> = key.into();

    let nonce = &data[0..12];
    let nonce = Nonce::from_slice(nonce);
    let enc_data = &data[12..];

    let cipher = Aes256Gcm::new(&key);

    let dec_data = cipher
        .decrypt(nonce, enc_data)
        .map_err(|e| Error::AESError(e.to_string()))?;

    Ok(dec_data)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_aes() {
        let s = b"hello, aes!";
        let key = gen_key();
        // let key = "x8WfNHpmhNdLZLiuV1YzlqeLBcJGPQuW".as_bytes();

        let enc = encrypt(&key, s).unwrap();
        let dec = decrypt(&key, &enc).unwrap();

        println!("{}", String::from_utf8_lossy(&dec));
    }

    #[test]
    fn test_gen_aeskey() {
        let key = gen_alphanum_key();
        println!("{}", key);
    }
}
