use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid aes key")]
    InvalidAESKey,

    #[error("aes error: {0}")]
    AESError(String),

    #[error("rsa error: {0}")]
    RSAError(String),

    #[error("rsa key to pem error: {0}")]
    RSAKeyToPemError(String),

    #[error("invalid license")]
    InvalidLicense,

    #[error("invalid signature, {0}")]
    InvalidSignature(String),

    #[error("invalid license json, {0}")]
    InvalidLicenseJson(String),

    #[error("base64 decode failed, {0}")]
    Base64DecodeFailed(String),
}
