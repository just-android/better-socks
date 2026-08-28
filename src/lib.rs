//! Asynchronous SOCKS5 client for Tokio.
//!
//! Fork of [`tokio-socks`](https://github.com/sticnarf/tokio-socks) with UDP
//! `ASSOCIATE` support via [`udp::Socks5UdpFramed`].
//!
//! Username/password authentication (RFC 1929) is sent in cleartext to the
//! proxy. There is no TLS-to-proxy transport in this crate.

use either::Either;
use futures_util::{
    future,
    stream::{self, Once, Stream},
};
use std::{
    borrow::Cow,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
    vec,
};
use tokio::net::lookup_host;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// A trait for objects which can be converted or resolved to one or more
/// `SocketAddr` values, which are going to be connected as the the proxy
/// server.
///
/// This trait is similar to `std::net::ToSocketAddrs` but allows asynchronous
/// name resolution.
pub trait ToProxyAddrs {
    type Output: Stream<Item = Result<SocketAddr>> + Unpin;

    fn to_proxy_addrs(&self) -> Self::Output;
}

macro_rules! trivial_impl_to_proxy_addrs {
    ($t: ty) => {
        impl ToProxyAddrs for $t {
            type Output = Once<future::Ready<Result<SocketAddr>>>;

            fn to_proxy_addrs(&self) -> Self::Output {
                stream::once(future::ready(Ok(SocketAddr::from(*self))))
            }
        }
    };
}

trivial_impl_to_proxy_addrs!(SocketAddr);
trivial_impl_to_proxy_addrs!((IpAddr, u16));
trivial_impl_to_proxy_addrs!((Ipv4Addr, u16));
trivial_impl_to_proxy_addrs!((Ipv6Addr, u16));
trivial_impl_to_proxy_addrs!(SocketAddrV4);
trivial_impl_to_proxy_addrs!(SocketAddrV6);

impl ToProxyAddrs for &[SocketAddr] {
    type Output = ProxyAddrsStream;

    fn to_proxy_addrs(&self) -> Self::Output {
        ProxyAddrsStream::from_addrs(self.to_vec())
    }
}

impl ToProxyAddrs for str {
    type Output = ProxyAddrsStream;

    fn to_proxy_addrs(&self) -> Self::Output {
        let host = self.to_owned();
        ProxyAddrsStream::lookup(async move { Ok(lookup_host(host).await?.collect()) })
    }
}

impl ToProxyAddrs for (&str, u16) {
    type Output = ProxyAddrsStream;

    fn to_proxy_addrs(&self) -> Self::Output {
        let host = self.0.to_owned();
        let port = self.1;
        ProxyAddrsStream::lookup(async move { Ok(lookup_host((host, port)).await?.collect()) })
    }
}

impl<T: ToProxyAddrs + ?Sized> ToProxyAddrs for &T {
    type Output = T::Output;

    fn to_proxy_addrs(&self) -> Self::Output {
        (**self).to_proxy_addrs()
    }
}

enum ProxyAddrsInner {
    Iter(vec::IntoIter<SocketAddr>),
    Lookup(Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>),
    Done,
}

/// Stream of resolved proxy server addresses.
pub struct ProxyAddrsStream {
    inner: ProxyAddrsInner,
}

impl ProxyAddrsStream {
    fn from_addrs(addrs: Vec<SocketAddr>) -> Self {
        Self {
            inner: ProxyAddrsInner::Iter(addrs.into_iter()),
        }
    }

    fn lookup<F>(fut: F) -> Self
    where
        F: Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'static,
    {
        Self {
            inner: ProxyAddrsInner::Lookup(Box::pin(fut)),
        }
    }
}

impl Stream for ProxyAddrsStream {
    type Item = Result<SocketAddr>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match &mut this.inner {
                ProxyAddrsInner::Iter(iter) => return Poll::Ready(iter.next().map(Ok)),
                ProxyAddrsInner::Lookup(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(addrs)) => {
                        this.inner = ProxyAddrsInner::Iter(addrs.into_iter());
                    },
                    Poll::Ready(Err(e)) => {
                        this.inner = ProxyAddrsInner::Done;
                        return Poll::Ready(Some(Err(e.into())));
                    },
                    Poll::Pending => return Poll::Pending,
                },
                ProxyAddrsInner::Done => return Poll::Ready(None),
            }
        }
    }
}

/// A SOCKS connection target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetAddr<'a> {
    /// Connect to an IP address.
    Ip(SocketAddr),

    /// Connect to a fully-qualified domain name.
    ///
    /// The domain name will be passed along to the proxy server and DNS lookup
    /// will happen there.
    Domain(Cow<'a, str>, u16),
}

impl TryFrom<TargetAddr<'_>> for SocketAddr {
    type Error = Error;

    fn try_from(item: TargetAddr<'_>) -> Result<Self> {
        match item {
            TargetAddr::Ip(addr) => Ok(addr),
            TargetAddr::Domain(_, _) => Err(Error::InvalidTargetAddress(
                "cannot convert a domain target to SocketAddr without DNS resolution",
            )),
        }
    }
}

impl TargetAddr<'_> {
    /// Creates owned `TargetAddr` by cloning. It is usually used to eliminate
    /// the lifetime bound.
    pub fn to_owned(&self) -> TargetAddr<'static> {
        match self {
            TargetAddr::Ip(addr) => TargetAddr::Ip(*addr),
            TargetAddr::Domain(domain, port) => TargetAddr::Domain(Cow::Owned(domain.clone().into_owned()), *port),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    pub fn set_port(&mut self, port: u16) {
        match self {
            TargetAddr::Ip(addr) => addr.set_port(port),
            TargetAddr::Domain(_, p) => *p = port,
        }
    }
}

impl ToSocketAddrs for TargetAddr<'_> {
    type Iter = Either<std::option::IntoIter<SocketAddr>, std::vec::IntoIter<SocketAddr>>;

    /// Resolves domain names with the local resolver. This bypasses SOCKS
    /// remote DNS and can leak queries; prefer passing the domain to the proxy.
    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        Ok(match self {
            TargetAddr::Ip(addr) => Either::Left(addr.to_socket_addrs()?),
            TargetAddr::Domain(domain, port) => Either::Right((&**domain, *port).to_socket_addrs()?),
        })
    }
}

/// A trait for objects that can be converted to `TargetAddr`.
pub trait IntoTargetAddr<'a> {
    /// Converts the value of self to a `TargetAddr`.
    fn into_target_addr(self) -> Result<TargetAddr<'a>>;
}

macro_rules! trivial_impl_into_target_addr {
    ($t: ty) => {
        impl<'a> IntoTargetAddr<'a> for $t {
            fn into_target_addr(self) -> Result<TargetAddr<'a>> {
                Ok(TargetAddr::Ip(SocketAddr::from(self)))
            }
        }
    };
}

trivial_impl_into_target_addr!(SocketAddr);
trivial_impl_into_target_addr!((IpAddr, u16));
trivial_impl_into_target_addr!((Ipv4Addr, u16));
trivial_impl_into_target_addr!((Ipv6Addr, u16));
trivial_impl_into_target_addr!(SocketAddrV4);
trivial_impl_into_target_addr!(SocketAddrV6);

impl<'a> IntoTargetAddr<'a> for TargetAddr<'a> {
    fn into_target_addr(self) -> Result<TargetAddr<'a>> {
        Ok(self)
    }
}

impl<'a> IntoTargetAddr<'a> for (&'a str, u16) {
    fn into_target_addr(self) -> Result<TargetAddr<'a>> {
        // Try IP address first
        if let Ok(addr) = self.0.parse::<IpAddr>() {
            return (addr, self.1).into_target_addr();
        }

        // Treat as domain name
        if self.0.len() > 255 {
            return Err(Error::InvalidTargetAddress("overlong domain"));
        }
        // TODO: Should we validate the domain format here?

        Ok(TargetAddr::Domain(self.0.into(), self.1))
    }
}

impl<'a> IntoTargetAddr<'a> for &'a str {
    fn into_target_addr(self) -> Result<TargetAddr<'a>> {
        // Try IP address first
        if let Ok(addr) = self.parse::<SocketAddr>() {
            return addr.into_target_addr();
        }

        // Unbracketed IPv6 host:port (e.g. `::1:80`) is not supported; use `[::1]:80`.
        let mut parts_iter = self.rsplitn(2, ':');
        let port: u16 = parts_iter
            .next()
            .and_then(|port_str| port_str.parse().ok())
            .ok_or(Error::InvalidTargetAddress("invalid address format"))?;
        let domain = parts_iter
            .next()
            .ok_or(Error::InvalidTargetAddress("invalid address format"))?;
        if domain.len() > 255 {
            return Err(Error::InvalidTargetAddress("overlong domain"));
        }
        Ok(TargetAddr::Domain(domain.into(), port))
    }
}

impl IntoTargetAddr<'static> for String {
    fn into_target_addr(mut self) -> Result<TargetAddr<'static>> {
        // Try IP address first
        if let Ok(addr) = self.parse::<SocketAddr>() {
            return addr.into_target_addr();
        }

        let mut parts_iter = self.rsplitn(2, ':');
        let port: u16 = parts_iter
            .next()
            .and_then(|port_str| port_str.parse().ok())
            .ok_or(Error::InvalidTargetAddress("invalid address format"))?;
        let domain_len = parts_iter
            .next()
            .ok_or(Error::InvalidTargetAddress("invalid address format"))?
            .len();
        if domain_len > 255 {
            return Err(Error::InvalidTargetAddress("overlong domain"));
        }
        self.truncate(domain_len);
        Ok(TargetAddr::Domain(self.into(), port))
    }
}

impl IntoTargetAddr<'static> for (String, u16) {
    fn into_target_addr(self) -> Result<TargetAddr<'static>> {
        let addr = (self.0.as_str(), self.1).into_target_addr()?;
        if let TargetAddr::Ip(addr) = addr {
            Ok(TargetAddr::Ip(addr))
        } else {
            Ok(TargetAddr::Domain(self.0.into(), self.1))
        }
    }
}

impl<'a, T> IntoTargetAddr<'a> for &'a T
where T: IntoTargetAddr<'a> + Copy
{
    fn into_target_addr(self) -> Result<TargetAddr<'a>> {
        (*self).into_target_addr()
    }
}

impl fmt::Display for TargetAddr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// Authentication methods
#[derive(Debug)]
enum Authentication<'a> {
    Password { username: &'a str, password: &'a str },
    None,
}

mod error;
pub mod tcp;
pub mod udp;

#[cfg(test)]
mod tests {
    use super::*;
    use futures_executor::block_on;
    use futures_util::StreamExt;

    fn to_proxy_addrs<T: ToProxyAddrs>(t: T) -> Result<Vec<SocketAddr>> {
        Ok(block_on(t.to_proxy_addrs().map(Result::unwrap).collect()))
    }

    #[test]
    fn converts_socket_addr_to_proxy_addrs() -> Result<()> {
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        let res = to_proxy_addrs(addr)?;
        assert_eq!(&res[..], &[addr]);
        Ok(())
    }

    #[test]
    fn converts_socket_addr_ref_to_proxy_addrs() -> Result<()> {
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        #[allow(clippy::needless_borrows_for_generic_args)]
        let res = to_proxy_addrs(&addr)?;
        assert_eq!(&res[..], &[addr]);
        Ok(())
    }

    #[test]
    fn converts_socket_addrs_to_proxy_addrs() -> Result<()> {
        let addrs = [
            SocketAddr::from(([1, 1, 1, 1], 443)),
            SocketAddr::from(([8, 8, 8, 8], 53)),
        ];
        let res = to_proxy_addrs(&addrs[..])?;
        assert_eq!(&res[..], &addrs);
        Ok(())
    }

    fn into_target_addr<'a, T>(t: T) -> Result<TargetAddr<'a>>
    where T: IntoTargetAddr<'a> {
        t.into_target_addr()
    }

    #[test]
    fn converts_socket_addr_to_target_addr() -> Result<()> {
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        let res = into_target_addr(addr)?;
        assert_eq!(TargetAddr::Ip(addr), res);
        let addr2 = SocketAddr::try_from(res)?;
        assert_eq!(addr, addr2);
        Ok(())
    }

    #[test]
    fn domain_target_does_not_convert_to_socket_addr() {
        let res = into_target_addr("www.example.com:80").unwrap();
        assert!(SocketAddr::try_from(res).is_err());
    }

    #[test]
    fn converts_socket_addr_ref_to_target_addr() -> Result<()> {
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        #[allow(clippy::needless_borrows_for_generic_args)]
        let res = into_target_addr(&addr)?;
        assert_eq!(TargetAddr::Ip(addr), res);
        Ok(())
    }

    #[test]
    fn converts_socket_addr_str_to_target_addr() -> Result<()> {
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        let ip_str = format!("{}", addr);
        let res = into_target_addr(ip_str.as_str())?;
        assert_eq!(TargetAddr::Ip(addr), res);
        Ok(())
    }

    #[test]
    fn converts_ip_str_and_port_target_addr() -> Result<()> {
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        let ip_str = format!("{}", addr.ip());
        let res = into_target_addr((ip_str.as_str(), addr.port()))?;
        assert_eq!(TargetAddr::Ip(addr), res);
        Ok(())
    }

    #[test]
    fn converts_domain_to_target_addr() -> Result<()> {
        let domain = "www.example.com:80";
        let res = into_target_addr(domain)?;
        assert_eq!(TargetAddr::Domain(Cow::Borrowed("www.example.com"), 80), res);

        let res = into_target_addr(domain.to_owned())?;
        assert_eq!(TargetAddr::Domain(Cow::Owned("www.example.com".to_owned()), 80), res);
        Ok(())
    }

    #[test]
    fn converts_domain_and_port_to_target_addr() -> Result<()> {
        let domain = "www.example.com";
        let res = into_target_addr((domain, 80))?;
        assert_eq!(TargetAddr::Domain(Cow::Borrowed("www.example.com"), 80), res);
        Ok(())
    }

    #[test]
    fn overlong_domain_to_target_addr_should_fail() {
        let domain = format!("www.{:a<1$}.com:80", 'a', 300);
        assert!(into_target_addr(domain.as_str()).is_err());
        let domain = format!("www.{:a<1$}.com", 'a', 300);
        assert!(into_target_addr((domain.as_str(), 80)).is_err());
    }

    #[test]
    fn addr_with_invalid_port_to_target_addr_should_fail() {
        let addr = "[ffff::1]:65536";
        assert!(into_target_addr(addr).is_err());
        let addr = "www.example.com:65536";
        assert!(into_target_addr(addr).is_err());
    }
