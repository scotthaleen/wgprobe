use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

const DUMMY_PEER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

pub struct RunIdentity {
    private_key: Zeroizing<String>,
    public_key: String,
}

impl RunIdentity {
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let contents = fs::read_to_string(path)
            .map(Zeroizing::new)
            .map_err(|source| KeyError::Read {
                path: path.to_owned(),
                source,
            })?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self, KeyError> {
        let key = contents.trim();
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(KeyError::InvalidContents);
        }
        let private_key = Zeroizing::new(key.to_owned());
        let config = wgprobe::ProbeConfig::from_parts(
            private_key.as_str(),
            DUMMY_PEER_KEY,
            "127.0.0.1:51820",
        )?;
        Ok(Self {
            public_key: config.client_public_key(),
            private_key,
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &str {
        &self.private_key
    }

    pub fn probe_config(
        &self,
        peer_public_key: &str,
        endpoint: impl Into<String>,
    ) -> Result<wgprobe::ProbeConfig, wgprobe::ConfigError> {
        wgprobe::ProbeConfig::from_parts(self.private_key(), peer_public_key, endpoint)
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("could not read key file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the private key must contain exactly one base64 value and no other content")]
    InvalidContents,
    #[error("invalid WireGuard private key: {0}")]
    Invalid(#[from] wgprobe::ConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn accepts_one_trimmed_key_and_derives_stable_identity() {
        let identity = RunIdentity::parse(&format!(" \n{KEY}\n\t")).unwrap();
        assert!(!identity.public_key().is_empty());
        assert_eq!(identity.private_key(), KEY);
    }

    #[test]
    fn rejects_multiline_and_configuration_content() {
        assert!(matches!(
            RunIdentity::parse(&format!("{KEY}\n{KEY}")),
            Err(KeyError::InvalidContents)
        ));
        assert!(matches!(
            RunIdentity::parse(&format!("PrivateKey = {KEY}")),
            Err(KeyError::InvalidContents)
        ));
    }
}
