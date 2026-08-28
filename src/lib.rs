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
