use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde::Serialize;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub struct ProbeConfig {
    pub(crate) private_key: StaticSecret,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) preshared_key: Option<[u8; 32]>,
    pub(crate) endpoint: String,
    pub(crate) address: Option<Ipv4Cidr>,
    pub(crate) dns_servers: Vec<IpAddr>,
    pub(crate) allowed_ips: Vec<Ipv4Cidr>,
}

impl ProbeConfig {
    pub fn from_parts(
        private_key: &str,
        peer_public_key: &str,
        endpoint: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            private_key: parse_private_key(private_key.trim())?,
            peer_public_key: PublicKey::from(parse_key("PublicKey", peer_public_key.trim())?),
            preshared_key: None,
            endpoint: endpoint.into(),
            address: None,
            dns_servers: Vec::new(),
            allowed_ips: Vec::new(),
        })
    }

    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let mut section = Section::None;
        let mut peer_sections = 0;
        let mut private_key = None;
        let mut peer_public_key = None;
        let mut preshared_key = None;
        let mut endpoint = None;
        let mut address = None;
        let mut dns_servers = Vec::new();
        let mut allowed_ips = Vec::new();

        for (index, raw_line) in input.lines().enumerate() {
            let line_number = index + 1;
            let line = raw_line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = match &line[1..line.len() - 1] {
                    "Interface" => Section::Interface,
                    "Peer" => {
                        peer_sections += 1;
                        Section::Peer
                    }
                    _ => Section::Other,
                };
                continue;
            }

            let (name, value) = line
                .split_once('=')
                .ok_or(ConfigError::InvalidLine { line: line_number })?;
            let (name, value) = (name.trim(), value.trim());
            match (section, name) {
                (Section::Interface, "PrivateKey") => private_key = Some(parse_private_key(value)?),
                (Section::Interface, "Address") => {
                    for item in split_list(value) {
                        if item.contains(':') {
                            continue;
                        }
                        address.get_or_insert(item.parse().map_err(|_| {
                            ConfigError::InvalidIpv4Cidr {
                                field: "Interface.Address",
                                value: item.to_owned(),
                            }
                        })?);
                    }
                }
                (Section::Interface, "DNS") => {
                    for item in split_list(value) {
                        if let Ok(address) = item.parse() {
                            dns_servers.push(address);
                        }
                    }
                }
                (Section::Peer, "PublicKey") => {
                    peer_public_key = Some(PublicKey::from(parse_key("PublicKey", value)?))
                }
                (Section::Peer, "PresharedKey") => {
                    preshared_key = Some(Zeroizing::new(parse_key("PresharedKey", value)?))
                }
                (Section::Peer, "Endpoint") => endpoint = Some(value.to_owned()),
                (Section::Peer, "AllowedIPs") => {
                    for item in split_list(value) {
                        if item.contains(':') {
                            continue;
                        }
                        allowed_ips.push(item.parse().map_err(|_| {
                            ConfigError::InvalidIpv4Cidr {
                                field: "Peer.AllowedIPs",
                                value: item.to_owned(),
                            }
                        })?);
                    }
                }
                _ => {}
            }
        }

        if peer_sections > 1 {
            return Err(ConfigError::MultiplePeers);
        }
        let private_key = private_key.ok_or(ConfigError::Missing("Interface.PrivateKey"))?;
        let peer_public_key = peer_public_key.ok_or(ConfigError::Missing("Peer.PublicKey"))?;
        let endpoint = endpoint.ok_or(ConfigError::Missing("Peer.Endpoint"))?;
        Ok(Self {
            private_key,
            peer_public_key,
            preshared_key: preshared_key.map(|key| *key),
            endpoint,
            address,
            dns_servers,
            allowed_ips,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn set_data_config(
        &mut self,
        address: Ipv4Cidr,
        dns_servers: Vec<IpAddr>,
        allowed_ips: Vec<Ipv4Cidr>,
    ) {
        self.address = Some(address);
        self.dns_servers = dns_servers;
        self.allowed_ips = allowed_ips;
    }

    /// Return the base64 public key derived from the configured private key.
    pub fn client_public_key(&self) -> String {
        STANDARD.encode(PublicKey::from(&self.private_key).as_bytes())
    }
}

impl Drop for ProbeConfig {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preshared_key {
            key.zeroize();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv4Cidr {
    address: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn address(self) -> Ipv4Addr {
        self.address
    }

    pub fn contains(self, address: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        u32::from(self.address) & mask == u32::from(address) & mask
    }
}

impl FromStr for Ipv4Cidr {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or(())?;
        let address = address.parse().map_err(|_| ())?;
        let prefix = prefix.parse().map_err(|_| ())?;
        if prefix > 32 {
            return Err(());
        }
        Ok(Self { address, prefix })
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix)
    }
}

#[derive(Clone, Copy)]
enum Section {
    None,
    Interface,
    Peer,
    Other,
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn parse_private_key(value: &str) -> Result<StaticSecret, ConfigError> {
    let mut bytes = parse_key("PrivateKey", value)?;
    let key = StaticSecret::from(bytes);
    bytes.zeroize();
    Ok(key)
}

fn parse_key(field: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    let mut bytes = [0u8; 32];
    decode_key_into(field, value, &mut bytes)?;
    Ok(bytes)
}

fn decode_key_into(
    field: &'static str,
    value: &str,
    bytes: &mut [u8; 32],
) -> Result<(), ConfigError> {
    let length = match STANDARD.decode_slice(value, bytes) {
        Ok(length) => length,
        Err(_) => {
            bytes.zeroize();
            return Err(ConfigError::InvalidKey(field));
        }
    };
    if length != bytes.len() {
        bytes.zeroize();
        return Err(ConfigError::InvalidKey(field));
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line} is not a section or key-value pair")]
    InvalidLine { line: usize },
    #[error("{0} must be a base64-encoded 32-byte key")]
    InvalidKey(&'static str),
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("the probe accepts exactly one [Peer] section")]
    MultiplePeers,
    #[error("{field} contains invalid IPv4 CIDR {value}")]
    InvalidIpv4Cidr { field: &'static str, value: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn parses_wireguard_data_fields_and_preshared_key() {
        let input = format!(
            "[Interface]\nPrivateKey={KEY}\nAddress=10.0.0.2/24, fd00::2/64\nDNS=10.0.0.53, corp.example, 2001:db8::53\n[Peer]\nPublicKey={KEY}\nPresharedKey={KEY}\nAllowedIPs=10.0.0.0/8, ::/0\nEndpoint=example.com:51820\n"
        );
        let config = ProbeConfig::parse(&input).unwrap();
        assert_eq!(config.endpoint(), "example.com:51820");
        assert_eq!(config.address.unwrap().to_string(), "10.0.0.2/24");
        assert_eq!(config.dns_servers.len(), 2);
        assert!(config.allowed_ips[0].contains("10.1.2.3".parse().unwrap()));
        assert!(config.preshared_key.is_some());
    }

    #[test]
    fn rejects_multiple_peers() {
        let input = format!(
            "[Interface]\nPrivateKey={KEY}\n[Peer]\nPublicKey={KEY}\nEndpoint=one:1\n[Peer]\nPublicKey={KEY}\nEndpoint=two:2\n"
        );
        assert!(matches!(
            ProbeConfig::parse(&input),
            Err(ConfigError::MultiplePeers)
        ));
    }

    #[test]
    fn wipes_key_buffer_after_partial_base64_decode_error() {
        let mut bytes = [0x55; 32];
        let result = decode_key_into(
            "PresharedKey",
            "//////////////////////////////////////////!=",
            &mut bytes,
        );
        assert_eq!(result, Err(ConfigError::InvalidKey("PresharedKey")));
        assert_eq!(bytes, [0; 32]);
    }

    #[test]
    fn valid_preshared_key_is_guarded_during_later_parse_failure() {
        let input = format!(
            "[Interface]\nPrivateKey={KEY}\n[Peer]\nPublicKey={KEY}\nPresharedKey=//////////////////////////////////////////8=\nAllowedIPs=invalid\nEndpoint=example.test:51820\n"
        );
        assert!(matches!(
            ProbeConfig::parse(&input),
            Err(ConfigError::InvalidIpv4Cidr { .. })
        ));
    }

    #[test]
    fn cidr_contains_addresses() {
        let cidr: Ipv4Cidr = "192.0.2.7/24".parse().unwrap();
        assert!(cidr.contains("192.0.2.200".parse().unwrap()));
        assert!(!cidr.contains("192.0.3.1".parse().unwrap()));
    }
}
