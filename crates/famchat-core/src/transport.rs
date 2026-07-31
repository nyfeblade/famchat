//! Pluggable transport: how two endpoints physically reach each other, kept
//! separate from *what* they say once connected.
//!
//! The handshake in [`crate::wire`] is generic over the byte stream, so a
//! transport only has to produce a duplex stream — by dialing a target, or by
//! accepting an incoming connection. Today there is one implementation,
//! [`TcpTransport`] (direct socket, good for LAN and testing). The Tor onion
//! transport slots in here behind the same two traits without the crypto above
//! ever knowing the difference.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// Any bidirectional byte stream we can run the Noise handshake over.
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DuplexStream for T {}

/// A type-erased duplex stream. `Box<dyn DuplexStream>` is itself
/// `AsyncRead + AsyncWrite + Unpin + Send`, so it drops straight into the
/// generic handshake and `tokio::io::split`.
pub type AnyStream = Box<dyn DuplexStream>;

/// A way to reach a peer: dial out, or bind and accept.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to `target` (a `host:port` or, for Tor, an `<addr>.onion:port`).
    async fn dial(&self, target: &str) -> Result<AnyStream>;
    /// Bind locally and return a listener that yields incoming streams.
    async fn listen(&self, bind: &str) -> Result<Box<dyn Listener>>;
    /// A short label for the transport, surfaced in the session info ("tcp"/"tor").
    fn kind(&self) -> &'static str;
}

/// An accepting endpoint produced by [`Transport::listen`].
#[async_trait]
pub trait Listener: Send {
    /// Wait for and accept the next incoming stream.
    async fn accept(&mut self) -> Result<AnyStream>;
    /// The address peers use to reach us (a `host:port`, or an `.onion`).
    fn local_addr(&self) -> String;
    /// Matches the parent transport's [`Transport::kind`].
    fn kind(&self) -> &'static str;
    /// Block until this endpoint is actually reachable by a peer, or `timeout`
    /// elapses (`Err`). Direct TCP is reachable the instant it binds, so the
    /// default returns immediately; a Tor onion service overrides this to wait for
    /// its descriptor to publish — until then the `.onion` exists but no client can
    /// reach it, so handing the address out early is misleading.
    ///
    /// Returns a boxed, `'static` future (rather than being an `async fn`) so the
    /// returned future owns what it needs instead of borrowing `&self`: a listener
    /// need not be `Sync` (the Tor one isn't), and this keeps the future `Send`.
    fn wait_until_reachable(
        &self,
        _timeout: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
        Box::pin(async { Ok(()) })
    }
}

/// Direct TCP transport — no anonymity, best for LAN and local testing. Works
/// across the internet too, but needs a reachable address / port-forwarding;
/// the Tor transport removes that requirement.
pub struct TcpTransport;

#[async_trait]
impl Transport for TcpTransport {
    async fn dial(&self, target: &str) -> Result<AnyStream> {
        let stream = TcpStream::connect(target)
            .await
            .map_err(|e| anyhow!("could not connect to {target}: {e}"))?;
        Ok(Box::new(stream))
    }

    async fn listen(&self, bind: &str) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| anyhow!("could not bind {bind}: {e}"))?;
        Ok(Box::new(TcpListenerHandle(listener)))
    }

    fn kind(&self) -> &'static str {
        "tcp"
    }
}

/// Wraps a bound [`TcpListener`] as a [`Listener`].
pub struct TcpListenerHandle(TcpListener);

#[async_trait]
impl Listener for TcpListenerHandle {
    async fn accept(&mut self) -> Result<AnyStream> {
        let (stream, _peer) = self.0.accept().await?;
        Ok(Box::new(stream))
    }

    fn local_addr(&self) -> String {
        self.0
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    fn kind(&self) -> &'static str {
        "tcp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// TcpTransport must dial and accept type-erased streams that still carry
    /// bytes end to end — the contract the session layer relies on.
    #[tokio::test]
    async fn tcp_transport_dial_and_accept() {
        let t = TcpTransport;
        let mut listener = t.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        assert_eq!(listener.kind(), "tcp");

        let server = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping!");
            s.write_all(b"pong!").await.unwrap();
            s.flush().await.unwrap();
        });

        let mut s = t.dial(&addr).await.unwrap();
        s.write_all(b"ping!").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");

        server.await.unwrap();
    }
}
