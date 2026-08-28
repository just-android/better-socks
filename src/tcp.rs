use crate::{Authentication, Error, IntoTargetAddr, Result, TargetAddr, ToProxyAddrs};
use futures_util::stream::{self, Fuse, Stream, StreamExt};
use std::{
    borrow::Borrow,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

#[repr(u8)]
#[derive(Clone, Copy)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
    #[allow(dead_code)]
    Associate = 0x03,
    #[cfg(feature = "tor")]
    TorResolve = 0xF0,
    #[cfg(feature = "tor")]
    TorResolvePtr = 0xF1,
}
