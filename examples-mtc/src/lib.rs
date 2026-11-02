mod cosigner_arg;
mod landmark_arg;

pub use crate::cosigner_arg::CosignerPath;
pub use crate::landmark_arg::LandmarkDefinition;
use clap::Args;
use clap::builder::TypedValueParser;
use rustls::RootCertStore;
use rustls::pki_types::mtc::CosignerPolicy;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::error::Error as StdError;
use std::path::PathBuf;

pub static DEFAULT_CA_CERT: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/ca_cert.pem"));

/// Command line args that are common to both the client and the server
#[derive(Args, Debug)]
pub struct CommonCmdArgs {
    #[command(flatten)]
    pub cert_args: CertArgs,
    /// Path to the CA certificate, optional.
    #[arg(long)]
    pub ca: Option<CaCertPath>,
    /// Path to a cosigner.json. Argument may be given multiple times, all given cosigners will be required.
    /// Optional.
    #[arg(long)]
    pub cosigner: Vec<CosignerPath>,
    /// Landmark definition: log number, followed by a colon, followed by the path to a `landmarks.txt`.
    /// Example: `--landmarks 1:/path/to/landmarks.txt`.
    /// Argument may be given multiple times.
    /// Optional.
    #[arg(long)]
    pub landmarks: Vec<LandmarkDefinition>,
    /// Port to connect to. Optional.
    #[arg(long, default_value_t = 4443)]
    pub port: u16,
}

/// Command line arguments about the certificate to use.
#[derive(Args, Debug)]
pub struct CertArgs {
    /// Path to the certificate to use. Optional.
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// Path to the private key to use with the given certificate. Optional.
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

impl CertArgs {
    /// Open the certificate and private key
    pub fn open(
        &self,
    ) -> Option<Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), PemError>> {
        fn inner(
            cert: &PathBuf,
            key: &PathBuf,
        ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), PemError> {
            let certs = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(key)?;
            Ok((certs, key))
        }

        match (&self.cert, &self.key) {
            (Some(cert), Some(key)) => Some(inner(cert, key)),
            (None, None) => None,
            _ => unreachable!(),
        }
    }
}

/// Command line argument value for the CA certificate.
#[derive(Debug, Clone)]
pub struct CaCertPath(PathBuf);

impl CaCertPath {
    /// Open the certificate
    pub fn open(&self) -> Result<CertificateDer<'_>, PemError> {
        CertificateDer::from_pem_file(&self.0)
    }
}

impl clap::builder::ValueParserFactory for CaCertPath {
    type Parser =
        clap::builder::MapValueParser<clap::builder::PathBufValueParser, fn(PathBuf) -> Self>;

    fn value_parser() -> Self::Parser {
        clap::builder::PathBufValueParser::new().map(Self)
    }
}

/// Create a RootCertStore from the common command line arguments
pub fn root_cert_store_from_common_args(
    args: &CommonCmdArgs,
) -> Result<RootCertStore, Box<dyn StdError>> {
    let CommonCmdArgs {
        cert_args: _,
        port: _,
        ca,
        cosigner,
        landmarks,
    } = args;

    let ca_cert = match ca {
        Some(path) => path.open()?,
        None => CertificateDer::from_pem_slice(DEFAULT_CA_CERT)?,
    };

    let cosigners = cosigner
        .iter()
        .map(|c| c.read())
        .collect::<Result<Vec<_>, _>>()?;

    let mut parsed_landmarks = Vec::new();
    for landmark in landmarks {
        parsed_landmarks.extend(landmark.read()?);
    }

    let mut roots = RootCertStore::empty();
    roots.add_mtc(
        ca_cert,
        CosignerPolicy::All,
        &[],
        cosigners,
        parsed_landmarks,
    )?;

    Ok(roots)
}
