use base64::Engine;
use regex::regex;
use rustls::pki_types::mtc::{Hash, TrustedSubtree};
use std::error::Error as StdError;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

/// Command line argument value format for landmark definitions
#[derive(Debug, Clone)]
pub struct LandmarkDefinition {
    log_number: u16,
    path: PathBuf,
}

impl LandmarkDefinition {
    /// Parse the landmark.txt
    pub fn read(&self) -> Result<Vec<TrustedSubtree>, Box<dyn StdError>> {
        let landmark_file = fs::read_to_string(&self.path)?;
        let regex = regex!(r"Landmark subtree \[(\d+), (\d+)\) with hash ([a-zA-Z0-9+/]+=)");

        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        regex
            .captures_iter(&landmark_file)
            .map(|cap| -> Result<_, Box<dyn StdError>> {
                let (_, [start, end, hash]) = cap.extract();
                let start = u64::from_str(start)?;
                let end = u64::from_str(end)?;

                let hash = engine.decode(hash)?;
                let hash = Hash::Sha256(hash.as_slice().try_into()?);

                Ok(TrustedSubtree::new(self.log_number, hash, start, end)
                    .ok_or("Invalid subtree data")?)
            })
            .collect()
    }
}

impl clap::builder::ValueParserFactory for LandmarkDefinition {
    type Parser = clap::builder::ValueParser;

    fn value_parser() -> Self::Parser {
        Self::Parser::new(
            |value: &str| -> Result<Self, Box<dyn StdError + Send + Sync>> {
                let (log_number, path) = value
                    .split_once(':')
                    .ok_or("Landmark definition missing the colon separator")?;
                let log_number = u16::from_str(log_number)?;
                Ok(LandmarkDefinition {
                    log_number,
                    path: PathBuf::from(path),
                })
            },
        )
    }
}
