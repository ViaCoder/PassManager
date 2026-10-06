use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("random number generator health check failed: {0}")]
    RngFailure(&'static str),
    #[error("authentication failed (wrong key, wrong password or tampered data)")]
    AuthFailed,
    #[error("KDF parameters below the security floor")]
    WeakKdf,
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("self-test failed: {0}")]
    SelfTest(&'static str),
    #[error("internal crypto error: {0}")]
    Internal(&'static str),
}

impl From<aws_lc_rs::error::Unspecified> for CryptoError {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        CryptoError::Internal("aws-lc operation failed")
    }
}
