/// Error type of `better-socks`
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Failure caused by an IO error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Failure when parsing a `String`.
    #[error("{0}")]
    ParseError(#[from] std::string::ParseError),
    /// Failure due to invalid target address. It contains the detailed error
    /// message.
    #[error("Target address is invalid: {0}")]
    InvalidTargetAddress(&'static str),
