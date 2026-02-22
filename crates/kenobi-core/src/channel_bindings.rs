pub trait Channel {
    type Error: std::error::Error;
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Error>;
}

#[cfg(feature = "native-tls")]
impl<S: std::io::Read + std::io::Write> Channel for native_tls::TlsStream<S> {
    type Error = native_tls::Error;

    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.tls_server_end_point()
    }
}
