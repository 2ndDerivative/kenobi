pub trait Channel {
    type Error: std::error::Error;
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Error>;
}

#[cfg(feature = "native-tls")]
impl<S: std::io::Read + std::io::Write> Channel for native_tls::TlsStream<S> {
    type Error = native_tls::Error;

    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.tls_server_end_point() {
            Ok(Some(v)) => {
                const PREFIX: &[u8] = b"tls-server-end-point:";
                let mut vec = Vec::with_capacity(PREFIX.len() + v.len());
                vec.extend_from_slice(PREFIX);
                vec.extend_from_slice(&v);
                Ok(Some(vec))
            }
            other => other,
        }
    }
}
