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
    /// Proxy server unreachable.
    #[error("Proxy server unreachable")]
    ProxyServerUnreachable,
    /// Proxy server returns an invalid version number.
    #[error("Invalid response version")]
    InvalidResponseVersion,
    /// No acceptable auth methods
    #[error("No acceptable auth methods")]
    NoAcceptableAuthMethods,
    /// Unknown auth method
    #[error("Unknown auth method")]
    UnknownAuthMethod,
