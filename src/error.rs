use std::fmt;

#[derive(Debug)]
pub enum Error {
    Config(String),
    Io(std::io::Error),
    Tls(String),
    Auth(String),
    Storage(String),
    Proxy(String),
    RateLimit(String),
    InvalidInput(String),
    NotFound(String),
    Internal(String),
    Security(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(msg) => write!(f, "Configuration error: {}", msg),
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::Tls(msg) => write!(f, "TLS error: {}", msg),
            Error::Security(msg) => write!(f, "Security error: {}", msg),
            Error::Auth(msg) => write!(f, "Authentication error: {}", msg),
            Error::Storage(msg) => write!(f, "Storage error: {}", msg),
            Error::Proxy(msg) => write!(f, "Proxy error: {}", msg),
            Error::RateLimit(msg) => write!(f, "Rate limit error: {}", msg),
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::NotFound(msg) => write!(f, "Not found: {}", msg),
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Config(err.to_string())
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(err: serde_yaml::Error) -> Self {
        Error::Config(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
