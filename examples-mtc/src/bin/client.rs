use clap::Parser;
use examples_mtc::{CommonCmdArgs, root_cert_store_from_common_args};
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

// cmdline args
/// Run a TLS client using Merkle Tree Certificates
#[derive(Parser, Debug)]
#[command(version)]
struct CmdArgs {
    /// Server name to connect to. Optional.
    #[arg(long, default_value = "a.example")]
    server_name: String,
    #[command(flatten)]
    common_args: CommonCmdArgs,
}

fn main() -> Result<(), Box<dyn StdError>> {
    let CmdArgs {
        server_name,
        common_args,
    } = CmdArgs::parse();

    let roots = root_cert_store_from_common_args(&common_args)?;
    let config_builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut config = match common_args.cert_args.open() {
        Some(res) => {
            let (cert, key) = res?;
            config_builder.with_client_auth_cert(cert, key)?
        }
        None => config_builder.with_no_client_auth(),
    };

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name.clone().try_into()?)?;
    let mut sock = TcpStream::connect(format!("{server_name}:{}", common_args.port))?;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);

    tls_stream.write_all(b"Hello from the client")?;
    tls_stream.flush()?;
    let mut buf = [0; 64];
    let len = tls_stream.read(&mut buf)?;
    if let Ok(msg) = str::from_utf8(&buf[..len]) {
        println!("Received str message from server: {msg}");
    } else {
        println!("Received byte message from server: {:?}", &buf[..len]);
    }

    Ok(())
}
