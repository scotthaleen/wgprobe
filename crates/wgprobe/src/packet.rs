use std::net::Ipv4Addr;

const IPV4_HEADER_LEN: usize = 20;

pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

fn ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; IPV4_HEADER_LEN + payload.len()];
    let total_len = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..].copy_from_slice(payload);
    let sum = checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

pub(crate) fn icmp_echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ip_id: u16,
    echo_id: u16,
    sequence: u16,
) -> Vec<u8> {
    let mut icmp = vec![0u8; 16];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&echo_id.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[8..].copy_from_slice(b"wgprobe1");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv4_packet(source, destination, 1, ip_id, &icmp)
}

pub(crate) fn is_icmp_echo_reply(
    packet: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    echo_id: u16,
    sequence: u16,
) -> bool {
    let Some((protocol, packet_source, packet_destination, payload)) = parse_ipv4(packet) else {
        return false;
    };
    protocol == 1
        && packet_source == source
        && packet_destination == destination
        && payload.len() >= 8
        && payload[0] == 0
        && payload[1] == 0
        && checksum(payload) == 0
        && payload[4..6] == echo_id.to_be_bytes()
        && payload[6..8] == sequence.to_be_bytes()
}

pub(crate) fn dns_query(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    transaction_id: u16,
    ip_id: u16,
    name: &str,
) -> Result<Vec<u8>, &'static str> {
    let mut dns = vec![0u8; 12];
    dns[0..2].copy_from_slice(&transaction_id.to_be_bytes());
    dns[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    dns[4..6].copy_from_slice(&1u16.to_be_bytes());
    encode_name(name, &mut dns)?;
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());

    let udp_len = 8 + dns.len();
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(&dns);
    let sum = match udp_checksum(source, destination, &udp) {
        0 => 0xffff,
        sum => sum,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    Ok(ipv4_packet(source, destination, 17, ip_id, &udp))
}

pub(crate) fn parse_dns_a_response(
    packet: &[u8],
    server: Ipv4Addr,
    client: Ipv4Addr,
    client_port: u16,
    transaction_id: u16,
    name: &str,
) -> Option<Vec<Ipv4Addr>> {
    let (protocol, source, destination, udp) = parse_ipv4(packet)?;
    if protocol != 17 || source != server || destination != client || udp.len() < 20 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp[0..2] != 53u16.to_be_bytes()
        || udp[2..4] != client_port.to_be_bytes()
        || udp_len < 20
        || udp_len > udp.len()
        || (udp[6..8] != [0, 0] && udp_checksum(source, destination, &udp[..udp_len]) != 0)
    {
        return None;
    }
    let dns = &udp[8..udp_len];
    if dns[0..2] != transaction_id.to_be_bytes() || dns[2] & 0x80 == 0 {
        return None;
    }
    let questions = u16::from_be_bytes([dns[4], dns[5]]);
    let answers = u16::from_be_bytes([dns[6], dns[7]]);
    if questions == 0 {
        return None;
    }
    let (matches, mut offset) = name_matches(dns, 12, name)?;
    if !matches || offset.checked_add(4)? > dns.len() {
        return None;
    }
    if dns[offset..offset + 2] != 1u16.to_be_bytes()
        || dns[offset + 2..offset + 4] != 1u16.to_be_bytes()
    {
        return None;
    }
    offset += 4;
    for _ in 1..questions {
        offset = skip_name(dns, offset)?;
        offset = offset.checked_add(4)?;
        if offset > dns.len() {
            return None;
        }
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(dns, offset)?;
        if offset + 10 > dns.len() {
            return None;
        }
        let kind = u16::from_be_bytes([dns[offset], dns[offset + 1]]);
        let class = u16::from_be_bytes([dns[offset + 2], dns[offset + 3]]);
        let length = usize::from(u16::from_be_bytes([dns[offset + 8], dns[offset + 9]]));
        offset += 10;
        if offset + length > dns.len() {
            return None;
        }
        if kind == 1 && class == 1 && length == 4 {
            addresses.push(Ipv4Addr::new(
                dns[offset],
                dns[offset + 1],
                dns[offset + 2],
                dns[offset + 3],
            ));
        }
        offset += length;
    }
    Some(addresses)
}

fn parse_ipv4(packet: &[u8]) -> Option<(u8, Ipv4Addr, Ipv4Addr, &[u8])> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if header_len < IPV4_HEADER_LEN
        || total_len < header_len
        || total_len > packet.len()
        || fragment & 0x3fff != 0
        || checksum(&packet[..header_len]) != 0
    {
        return None;
    }
    Some((
        packet[9],
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        &packet[header_len..total_len],
    ))
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    checksum(&pseudo)
}

fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), &'static str> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err("DNS name must contain 1 to 253 characters");
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err("DNS labels must contain 1 to 63 ASCII characters");
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut end = None;
    let mut jumps = 0usize;
    let mut expanded_len = 1usize;
    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(offset + 1)?;
            end.get_or_insert(offset + 2);
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            if pointer >= offset {
                return None;
            }
            offset = pointer;
            jumps += 1;
            if jumps > 128 {
                return None;
            }
            continue;
        }
        offset += 1;
        if length == 0 {
            return Some(end.unwrap_or(offset));
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        expanded_len = expanded_len.checked_add(usize::from(length) + 1)?;
        if expanded_len > 255 {
            return None;
        }
        offset = offset.checked_add(usize::from(length))?;
        if offset > packet.len() {
            return None;
        }
    }
}

fn name_matches(packet: &[u8], start: usize, expected: &str) -> Option<(bool, usize)> {
    let mut offset = start;
    let mut end = None;
    let mut labels = expected.trim_end_matches('.').split('.');
    let mut expanded_len = 1usize;
    let mut jumps = 0usize;

    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(offset + 1)?;
            end.get_or_insert(offset + 2);
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            if pointer >= offset {
                return None;
            }
            offset = pointer;
            jumps += 1;
            if jumps > 128 {
                return None;
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        offset += 1;
        if length == 0 {
            return Some((labels.next().is_none(), end.unwrap_or(offset)));
        }
        let length = usize::from(length);
        if length > 63 {
            return None;
        }
        expanded_len = expanded_len.checked_add(length + 1)?;
        if expanded_len > 255 {
            return None;
        }
        let label = packet.get(offset..offset.checked_add(length)?)?;
        let matches = labels
            .next()
            .is_some_and(|expected| label.eq_ignore_ascii_case(expected.as_bytes()));
        if !matches {
            return Some((false, end.unwrap_or(offset + length)));
        }
        offset += length;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_valid_ipv4_and_icmp_checksums() {
        let packet = icmp_echo_request(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            7,
            8,
            9,
        );
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(checksum(&packet[20..]), 0);
        assert_eq!(&packet[2..4], &(36u16.to_be_bytes()));
    }

    #[test]
    fn encodes_valid_udp_dns_query() {
        let packet = dns_query(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.53".parse().unwrap(),
            40000,
            123,
            456,
            "example.com",
        )
        .unwrap();
        assert_eq!(checksum(&packet[..20]), 0);
        let udp = &packet[20..];
        assert_eq!(
            udp_checksum(
                "10.0.0.2".parse().unwrap(),
                "10.0.0.53".parse().unwrap(),
                udp
            ),
            0
        );
    }

    #[test]
    fn rejects_invalid_dns_names() {
        assert!(
            dns_query(
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                1,
                1,
                1,
                "bad..name"
            )
            .is_err()
        );
    }

    #[test]
    fn parses_matching_dns_a_response() {
        let client = "10.0.0.2".parse().unwrap();
        let server = "10.0.0.53".parse().unwrap();
        let mut packet = dns_query(client, server, 40000, 123, 456, "example.com").unwrap();
        packet[12..16].copy_from_slice(&server.octets());
        packet[16..20].copy_from_slice(&client.octets());
        packet[20..22].copy_from_slice(&53u16.to_be_bytes());
        packet[22..24].copy_from_slice(&40000u16.to_be_bytes());
        packet[30] = 0x81;
        packet[31] = 0x80;
        packet[34..36].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 10,
        ]);
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[24..26].copy_from_slice(&(total_len - 20).to_be_bytes());
        packet[26..28].fill(0);
        packet[10..12].fill(0);
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        let answers =
            parse_dns_a_response(&packet, server, client, 40000, 123, "example.com").unwrap();
        assert_eq!(answers, ["192.0.2.10".parse::<Ipv4Addr>().unwrap()]);
        assert!(
            parse_dns_a_response(&packet, server, client, 40000, 123, "other.example").is_none()
        );
    }

    #[test]
    fn dns_question_matching_is_case_insensitive() {
        let client = "10.0.0.2".parse().unwrap();
        let server = "10.0.0.53".parse().unwrap();
        let mut packet = dns_query(client, server, 40000, 123, 456, "example.com").unwrap();
        packet[12..16].copy_from_slice(&server.octets());
        packet[16..20].copy_from_slice(&client.octets());
        packet[20..22].copy_from_slice(&53u16.to_be_bytes());
        packet[22..24].copy_from_slice(&40000u16.to_be_bytes());
        packet[30] = 0x81;
        packet[31] = 0x80;
        packet[41..48].copy_from_slice(b"EXAMPLE");
        packet[49..52].copy_from_slice(b"COM");
        packet[26..28].fill(0);
        packet[10..12].fill(0);
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        assert!(parse_dns_a_response(&packet, server, client, 40000, 123, "example.com").is_some());
    }

    #[test]
    fn follows_backward_dns_compression_pointer() {
        let mut packet = Vec::new();
        encode_name("example.com", &mut packet).unwrap();
        let compressed = packet.len();
        packet.extend_from_slice(&[0xc0, 0x00]);

        assert_eq!(
            name_matches(&packet, compressed, "EXAMPLE.COM"),
            Some((true, compressed + 2))
        );
        assert_eq!(skip_name(&packet, compressed), Some(compressed + 2));
    }

    #[test]
    fn rejects_forward_dns_compression_pointer() {
        assert_eq!(name_matches(&[0xc0, 0x02, 0], 0, "example.com"), None);
    }

    #[test]
    fn rejects_dns_question_compression_loop() {
        let client = "10.0.0.2".parse().unwrap();
        let server = "10.0.0.53".parse().unwrap();
        let mut packet = dns_query(client, server, 40000, 123, 456, "example.com").unwrap();
        packet[12..16].copy_from_slice(&server.octets());
        packet[16..20].copy_from_slice(&client.octets());
        packet[20..22].copy_from_slice(&53u16.to_be_bytes());
        packet[22..24].copy_from_slice(&40000u16.to_be_bytes());
        packet[30] = 0x81;
        packet[40..42].copy_from_slice(&[0xc0, 0x0c]);
        packet[26..28].fill(0);
        packet[10..12].fill(0);
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        assert!(parse_dns_a_response(&packet, server, client, 40000, 123, "example.com").is_none());
    }

    #[test]
    fn rejects_fragmented_ipv4_packets() {
        let mut packet = icmp_echo_request(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            7,
            8,
            9,
        );
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        packet[10..12].fill(0);
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());

        assert!(parse_ipv4(&packet).is_none());
    }

    #[test]
    fn rejects_dns_response_with_short_declared_udp_payload() {
        let client = "10.0.0.2".parse().unwrap();
        let server = "10.0.0.53".parse().unwrap();
        let mut packet = dns_query(client, server, 40000, 123, 456, "example.com").unwrap();
        packet[12..16].copy_from_slice(&server.octets());
        packet[16..20].copy_from_slice(&client.octets());
        packet[20..22].copy_from_slice(&53u16.to_be_bytes());
        packet[22..24].copy_from_slice(&40000u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet[26..28].fill(0);
        packet[10..12].fill(0);
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        assert!(parse_dns_a_response(&packet, server, client, 40000, 123, "example.com").is_none());
    }
}
