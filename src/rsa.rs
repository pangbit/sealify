use rsa::{
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

use crate::{Error, Result};

pub fn gen_key(bit_size: usize) -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let prikey = RsaPrivateKey::new(&mut rng, bit_size).unwrap();
    let pubkey = RsaPublicKey::from(&prikey);

    let pripem = prikey
        .to_pkcs8_pem(LineEnding::CRLF)
        .map_err(|e| Error::RSAKeyToPemError(e.to_string()))?
        .to_string();

    let pubpem = pubkey
        .to_public_key_pem(LineEnding::CRLF)
        .map_err(|e| Error::RSAKeyToPemError(e.to_string()))?;

    Ok((pubpem, pripem))
}

pub fn encrypt(pubkey: &str, data: &[u8]) -> Result<Vec<u8>> {
    let pubkey =
        RsaPublicKey::from_public_key_pem(pubkey).map_err(|e| Error::RSAError(e.to_string()))?;

    let mut rng = rand::thread_rng();

    let ciphertext = pubkey
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|e| Error::RSAError(e.to_string()))?;

    Ok(ciphertext)
}

pub fn decrypt(prikey: &str, data: &[u8]) -> Result<Vec<u8>> {
    let prikey =
        RsaPrivateKey::from_pkcs8_pem(prikey).map_err(|e| Error::RSAError(e.to_string()))?;

    prikey
        .decrypt(Pkcs1v15Encrypt, data)
        .map_err(|e| Error::RSAError(e.to_string()))
}

pub fn sign(prikey: &str, data: &[u8]) -> Result<Vec<u8>> {
    let prikey =
        RsaPrivateKey::from_pkcs8_pem(prikey).map_err(|e| Error::RSAError(e.to_string()))?;
    let signkey = SigningKey::<Sha256>::new(prikey);

    let mut rng = rand::thread_rng();
    let signature = signkey.sign_with_rng(&mut rng, data);

    Ok(signature.to_vec())
}

pub fn verify(pubkey: &str, data: &[u8], signature: &[u8]) -> Result<()> {
    let pubkey =
        RsaPublicKey::from_public_key_pem(pubkey).map_err(|e| Error::RSAError(e.to_string()))?;

    let verifykey = VerifyingKey::<Sha256>::new(pubkey);
    let signature =
        Signature::try_from(signature).map_err(|e| Error::InvalidSignature(e.to_string()))?;

    verifykey
        .verify(data, &signature)
        .map_err(|e| Error::RSAError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa() {
        let (pubkey, prikey) = gen_key(2048).unwrap();
        println!("{}", pubkey);
        println!("{}", prikey);

        let data = b"hello, rsa";
        let enc_data = encrypt(&pubkey, data).unwrap();
        let dec_data = decrypt(&prikey, &enc_data).unwrap();

        println!("{}", String::from_utf8_lossy(&dec_data));
    }

    #[test]
    fn test_rsa_sign() {
        let (pubkey, prikey) = gen_key(2048).unwrap();
        println!("{}", pubkey);
        println!("{}", prikey);

        let data = b"hello, rsa sign";
        let signature = sign(&prikey, data).unwrap();

        let result = verify(&pubkey, data, &signature);
        println!("{:?}", result);
    }

    #[test]
    fn test_gen_rsakey() {
        let (pubkey, prikey) = gen_key(2048).unwrap();
        println!("{}", pubkey);
        println!("{}", prikey);
    }
}
