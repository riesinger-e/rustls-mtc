use base64::Engine;
use clap::builder::TypedValueParser;
use rustls::pki_types::mtc::Cosigner;
use serde::Deserialize;
use serde::de::StdError;
use std::borrow::Cow;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

/// Command line argument value for the cosigner.json
#[derive(Debug, Clone)]
pub struct CosignerPath(PathBuf);

impl CosignerPath {
    /// Parse the cosigner.json
    pub fn read(&self) -> Result<Cosigner<'static>, Box<dyn StdError>> {
        let file = File::open(&self.0)?;
        let CosignerFormat { id, public_key } = serde_json::from_reader(file)?;

        let oid_parts = id
            .split('.')
            .map(u64::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        let id = x509_parser::asn1_rs::Oid::from_relative(&oid_parts)?.into_cow();

        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );
        let public_key = engine.decode(&public_key)?;

        let cosigner = Cosigner {
            id: Cow::Owned(id.into_owned()),
            // we just assume ML-DSA-44
            signature_algorithm: rustls::pki_types::alg_id::ML_DSA_44,
            public_key: Cow::Owned(public_key),
        };
        Ok(cosigner)
    }
}

impl clap::builder::ValueParserFactory for CosignerPath {
    type Parser =
        clap::builder::MapValueParser<clap::builder::PathBufValueParser, fn(PathBuf) -> Self>;

    fn value_parser() -> Self::Parser {
        clap::builder::PathBufValueParser::new().map(Self)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CosignerFormat {
    id: String,
    public_key: String,
}
