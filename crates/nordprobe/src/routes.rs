use std::net::Ipv4Addr;

use wgprobe::{Ipv4Cidr, allowed_ips_excluding};

const NORD_DNS_SERVERS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(103, 86, 96, 100),
    Ipv4Addr::new(103, 86, 99, 100),
];

pub fn parse_bypasses(input: &str) -> Result<Vec<Ipv4Cidr>, String> {
    input
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("bypass entry must be an IPv4 CIDR, got {value}"))
        })
        .collect()
}

pub fn allowed_ips(input: &str) -> Result<Vec<Ipv4Cidr>, String> {
    let allowed = allowed_ips_excluding(&parse_bypasses(input)?);
    if allowed.is_empty() {
        return Err("bypass entries exclude all IPv4 addresses".into());
    }
    Ok(allowed)
}

pub fn export_allowed_ips(input: &str) -> Result<Vec<Ipv4Cidr>, String> {
    let allowed = allowed_ips(input)?;
    for server in NORD_DNS_SERVERS {
        if !allowed.iter().any(|cidr| cidr.contains(server)) {
            return Err(format!("Nord DNS server {server} is inside a bypass CIDR"));
        }
    }
    Ok(allowed)
}

pub fn format_allowed_ips(allowed: &[Ipv4Cidr]) -> String {
    allowed
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn allowed_ips_line(input: &str) -> Result<String, String> {
    Ok(format!(
        "AllowedIPs = {}",
        format_allowed_ips(&allowed_ips(input)?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comma_and_space_separated_bypasses() {
        let bypasses = parse_bypasses("10.0.0.0/8, 192.168.0.0/16\n172.16.0.0/12").unwrap();
        assert_eq!(bypasses.len(), 3);
    }

    #[test]
    fn formats_generated_allowed_ips() {
        assert_eq!(
            allowed_ips_line("128.0.0.0/2, 192.0.0.0/2").unwrap(),
            "AllowedIPs = 0.0.0.0/1"
        );
        assert!(allowed_ips_line("invalid").is_err());
        assert!(allowed_ips_line("0.0.0.0/0").is_err());
    }

    #[test]
    fn export_routes_must_include_both_nord_dns_servers() {
        assert!(export_allowed_ips("103.86.96.100/32").is_err());
        assert!(export_allowed_ips("103.86.99.100/32").is_err());
        assert!(export_allowed_ips("10.0.0.0/8").is_ok());
    }
}
