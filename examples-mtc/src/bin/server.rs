use clap::Parser;
use examples_mtc::{CommonCmdArgs, root_cert_store_from_common_args};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

// cmdline args
/// Run a TLS server using Merkle Tree Certificates
#[derive(Parser, Debug)]
#[command(version)]
struct CmdArgs {
    /// enforce TLS client authentication, off by default
    #[arg(long, default_value_t = false)]
    client_auth: bool,
    #[command(flatten)]
    common_args: CommonCmdArgs,
}

static DEFAULT_CERT: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert_0_0.pem"));
static DEFAULT_KEY: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/server.pem"));

fn main() -> Result<(), Box<dyn StdError>> {
    let CmdArgs {
        client_auth,
        common_args,
    } = CmdArgs::parse();

    let (certs, key) = match common_args.cert_args.open() {
        Some(res) => res?,
        None => {
            let cert =
                CertificateDer::pem_slice_iter(DEFAULT_CERT).collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_slice(DEFAULT_KEY)?;
            (cert, key)
        }
    };

    let config_builder = if client_auth {
        let roots = root_cert_store_from_common_args(&common_args)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

        rustls::ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        rustls::ServerConfig::builder().with_no_client_auth()
    };
    let config = config_builder.with_single_cert(certs, key)?;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", common_args.port))?;
    let (mut tcp_stream, _) = listener.accept()?;
    let mut conn = rustls::ServerConnection::new(Arc::new(config))?;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);

    tls_stream.write_all(b"Hello from the server")?;
    tls_stream.flush()?;
    let mut buf = [0; 64];
    let len = tls_stream.read(&mut buf)?;
    if let Ok(msg) = str::from_utf8(&buf[..len]) {
        println!("Received str message from client: {msg}");
    } else {
        println!("Received byte message from client: {:?}", &buf[..len]);
    }

    Ok(())
}
