use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const INVENTORY_URL: &str = "https://api.nordvpn.com/v1/servers";
const INVENTORY_QUERY: [(&str, &str); 14] = [
    ("limit", "10000"),
    ("filters[servers.status]", "online"),
    ("filters[servers_technologies][identifier]", "wireguard_udp"),
    ("filters[servers_technologies][pivot][status]", "online"),
    ("fields[servers.name]", ""),
    ("fields[servers.hostname]", ""),
    ("fields[servers.station]", ""),
    ("fields[servers.load]", ""),
    ("fields[servers.status]", ""),
    ("fields[servers.locations.country.name]", ""),
    ("fields[servers.locations.country.city.name]", ""),
    ("fields[servers.technologies.identifier]", ""),
    ("fields[servers.technologies.metadata]", ""),
    ("fields[servers.technologies.pivot.status]", ""),
];
const MAX_INVENTORY_BYTES: u64 = 64 * 1024 * 1024;
const CACHE_SCHEMA_VERSION: u8 = 1;
pub const CACHE_STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
static CACHE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NordTarget {
    pub name: String,
    pub hostname: String,
    pub endpoint: SocketAddr,
    pub public_key: String,
    pub country: String,
    pub city: String,
    pub load: u8,
}

#[derive(Debug)]
pub struct CachedInventory {
    pub targets: Vec<NordTarget>,
    pub fetched_at: SystemTime,
}

#[derive(Debug, Deserialize, Serialize)]
struct CacheDocument {
    schema_version: u8,
    fetched_at_unix_seconds: u64,
    targets: Vec<NordTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitySummary {
    pub country: String,
    pub city: String,
    pub count: usize,
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("Nord inventory request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Nord inventory JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Nord inventory response exceeded the {MAX_INVENTORY_BYTES}-byte limit")]
    BodyTooLarge,
    #[error("could not read Nord inventory response: {0}")]
    Body(#[source] std::io::Error),
    #[error("Nord inventory response is not valid UTF-8")]
    BodyEncoding,
    #[error("Nord inventory contained no usable online WireGuard candidates")]
    NoUsableTargets,
}

pub fn fetch() -> Result<Vec<NordTarget>, InventoryError> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("nordprobe/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client
        .get(INVENTORY_URL)
        .query(&INVENTORY_QUERY)
        .send()?
        .error_for_status()?;
    parse(&read_limited(response, MAX_INVENTORY_BYTES)?)
}

pub fn load_cache() -> Result<Option<CachedInventory>, String> {
    let path = cache_path()?;
    load_cache_from(&path)
}

fn load_cache_from(path: &std::path::Path) -> Result<Option<CachedInventory>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "could not read inventory cache {}: {error}",
                path.display()
            ));
        }
    };
    if bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err(format!(
            "inventory cache {} exceeds the {MAX_INVENTORY_BYTES}-byte limit",
            path.display()
        ));
    }
    let document: CacheDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("inventory cache {} is invalid: {error}", path.display()))?;
    if document.schema_version != CACHE_SCHEMA_VERSION {
        return Err(format!(
            "inventory cache {} uses unsupported schema version {}",
            path.display(),
            document.schema_version
        ));
    }
    if document.targets.is_empty() {
        return Err(format!(
            "inventory cache {} contains no candidates",
            path.display()
        ));
    }
    if document.targets.iter().any(|target| {
        target.name.is_empty()
            || target.hostname.is_empty()
            || target.country.is_empty()
            || target.city.is_empty()
            || target.name.chars().any(char::is_control)
            || target.hostname.chars().any(char::is_control)
            || target.country.chars().any(char::is_control)
            || target.city.chars().any(char::is_control)
            || !is_wireguard_key(&target.public_key)
    }) {
        return Err(format!(
            "inventory cache {} contains invalid candidates",
            path.display()
        ));
    }
    let fetched_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(document.fetched_at_unix_seconds))
        .ok_or_else(|| {
            format!(
                "inventory cache {} has an invalid timestamp",
                path.display()
            )
        })?;
    Ok(Some(CachedInventory {
        targets: document.targets,
        fetched_at,
    }))
}

pub fn store_cache(targets: &[NordTarget], fetched_at: SystemTime) -> Result<PathBuf, String> {
    let path = cache_path()?;
    store_cache_to(&path, targets, fetched_at)?;
    Ok(path)
}

fn store_cache_to(
    path: &std::path::Path,
    targets: &[NordTarget],
    fetched_at: SystemTime,
) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "inventory cache path has no parent directory".to_owned())?;
    fs::create_dir_all(directory).map_err(|error| {
        format!(
            "could not create inventory cache directory {}: {error}",
            directory.display()
        )
    })?;
    let fetched_at_unix_seconds = fetched_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| "could not cache inventory with a pre-epoch timestamp".to_owned())?
        .as_secs();
    let document = CacheDocument {
        schema_version: CACHE_SCHEMA_VERSION,
        fetched_at_unix_seconds,
        targets: targets.to_vec(),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("could not encode inventory cache: {error}"))?;
    let nonce = CACHE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("json.tmp-{}-{nonce}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| {
        format!(
            "could not write inventory cache {}: {error}",
            temporary.display()
        )
    })?;
    if let Err(first_error) = fs::rename(&temporary, path) {
        if fs::symlink_metadata(path).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(format!(
                "could not replace inventory cache {}: {first_error}",
                path.display()
            ));
        }
        let backup = path.with_extension(format!("json.bak-{}-{nonce}", std::process::id()));
        if let Err(backup_error) = fs::rename(path, &backup) {
            let _ = fs::remove_file(&temporary);
            return Err(format!(
                "could not replace inventory cache {}: {first_error}; could not preserve the existing cache: {backup_error}",
                path.display()
            ));
        }
        if let Err(install_error) = fs::rename(&temporary, path) {
            let restore_error = fs::rename(&backup, path).err();
            let _ = fs::remove_file(&temporary);
            return Err(match restore_error {
                Some(restore_error) => format!(
                    "could not install inventory cache {}: {install_error}; the previous cache remains at {} because restoration failed: {restore_error}",
                    path.display(),
                    backup.display()
                ),
                None => format!(
                    "could not install inventory cache {}: {install_error}; restored the previous cache",
                    path.display()
                ),
            });
        }
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

pub fn cache_path() -> Result<PathBuf, String> {
    dirs::cache_dir()
        .map(|directory| directory.join("nordprobe").join("inventory.json"))
        .ok_or_else(|| "no platform cache directory is available".to_owned())
}

pub fn parse(json: &str) -> Result<Vec<NordTarget>, InventoryError> {
    let records: Vec<serde_json::Value> = serde_json::from_str(json)?;
    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for record in records {
        let Ok(server) = serde_json::from_value::<ApiServer>(record) else {
            continue;
        };
        if server.status != "online" {
            continue;
        }
        let Some(location) = server.locations.first() else {
            continue;
        };
        let Some(technology) = server.technologies.iter().find(|technology| {
            technology.identifier == "wireguard_udp" && technology.pivot.status == "online"
        }) else {
            continue;
        };
        let Some(public_key) = technology
            .metadata
            .iter()
            .find(|item| item.name == "public_key")
            .map(|item| item.value.trim())
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Ok(ip) = server.station.parse::<IpAddr>() else {
            continue;
        };
        let name = sanitize_display(&server.name);
        let hostname = sanitize_display(&server.hostname);
        let country = sanitize_display(&location.country.name);
        let city = sanitize_display(&location.country.city.name);
        if name.is_empty()
            || hostname.is_empty()
            || country.is_empty()
            || city.is_empty()
            || !is_wireguard_key(public_key)
        {
            continue;
        }
        let endpoint = SocketAddr::new(ip, 51820);
        if !seen.insert((endpoint, public_key.to_owned())) {
            continue;
        }
        targets.push(NordTarget {
            name,
            hostname,
            endpoint,
            public_key: public_key.to_owned(),
            country,
            city,
            load: server.load,
        });
    }

    if targets.is_empty() {
        return Err(InventoryError::NoUsableTargets);
    }

    targets.sort_by(|left, right| {
        (
            &left.country,
            &left.city,
            &left.name,
            left.load,
            &left.hostname,
        )
            .cmp(&(
                &right.country,
                &right.city,
                &right.name,
                right.load,
                &right.hostname,
            ))
    });
    Ok(targets)
}

fn read_limited(reader: impl Read, maximum: u64) -> Result<String, InventoryError> {
    let mut body = Vec::new();
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(InventoryError::Body)?;
    if body.len() as u64 > maximum {
        return Err(InventoryError::BodyTooLarge);
    }
    String::from_utf8(body).map_err(|_| InventoryError::BodyEncoding)
}

fn sanitize_display(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn is_wireguard_key(value: &str) -> bool {
    let mut bytes = [0u8; 32];
    STANDARD
        .decode_slice(value, &mut bytes)
        .is_ok_and(|length| length == bytes.len())
}

pub fn cities(targets: &[NordTarget], filter: &str) -> Vec<CitySummary> {
    let filter = filter.trim().to_ascii_lowercase();
    let mut counts = BTreeMap::<(&str, &str), usize>::new();
    for target in targets {
        if !filter.is_empty()
            && !target.country.to_ascii_lowercase().contains(&filter)
            && !target.city.to_ascii_lowercase().contains(&filter)
        {
            continue;
        }
        *counts.entry((&target.country, &target.city)).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((country, city), count)| CitySummary {
            country: country.to_owned(),
            city: city.to_owned(),
            count,
        })
        .collect()
}

pub fn city_targets(targets: &[NordTarget], country: &str, city: &str) -> Vec<NordTarget> {
    let mut selected: Vec<_> = targets
        .iter()
        .filter(|target| target.country == country && target.city == city)
        .cloned()
        .collect();
    selected.sort_by(|left, right| {
        (left.load, &left.name, &left.hostname).cmp(&(right.load, &right.name, &right.hostname))
    });
    selected
}

#[derive(Debug, Deserialize)]
struct ApiServer {
    name: String,
    hostname: String,
    station: String,
    load: u8,
    status: String,
    #[serde(default)]
    locations: Vec<ApiLocation>,
    #[serde(default)]
    technologies: Vec<ApiTechnology>,
}

#[derive(Debug, Deserialize)]
struct ApiLocation {
    country: ApiCountry,
}

#[derive(Debug, Deserialize)]
struct ApiCountry {
    name: String,
    city: ApiCity,
}

#[derive(Debug, Deserialize)]
struct ApiCity {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ApiTechnology {
    identifier: String,
    #[serde(default)]
    metadata: Vec<ApiMetadata>,
    pivot: ApiPivot,
}

#[derive(Debug, Deserialize)]
struct ApiMetadata {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct ApiPivot {
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/servers.json");

    #[test]
    fn extracts_online_wireguard_targets_and_deduplicates() {
        let targets = parse(FIXTURE).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].city, "Atlanta");
        assert_eq!(targets[0].endpoint.to_string(), "192.0.2.20:51820");
        assert_eq!(
            targets[0].public_key,
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        );
        assert_eq!(targets[1].city, "Denver");
    }

    #[test]
    fn aggregates_and_filters_city_names() {
        let targets = parse(FIXTURE).unwrap();
        let summaries = cities(&targets, "den");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].city, "Denver");
        assert_eq!(summaries[0].count, 1);
    }

    #[test]
    fn strips_remote_control_characters_from_display_text() {
        assert_eq!(sanitize_display("Den\u{1b}[31mver\n"), "Den[31mver");
    }

    #[test]
    fn rejects_inventory_without_usable_candidates() {
        assert!(matches!(parse("[]"), Err(InventoryError::NoUsableTargets)));
        assert!(matches!(
            parse(r#"[{"status":"online","name":7},{"status":"offline"}]"#),
            Err(InventoryError::NoUsableTargets)
        ));
    }

    #[test]
    fn skips_malformed_records_while_retaining_valid_records() {
        let fixture: Vec<serde_json::Value> = serde_json::from_str(FIXTURE).unwrap();
        let document = serde_json::to_string(&serde_json::json!([
            {"status": "offline", "load": "malformed irrelevant record"},
            {"status": "online", "name": 7},
            fixture[0]
        ]))
        .unwrap();
        let targets = parse(&document).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].city, "Atlanta");
    }

    #[test]
    fn rejects_invalid_top_level_documents() {
        assert!(matches!(parse("not json"), Err(InventoryError::Json(_))));
        assert!(matches!(parse("{}"), Err(InventoryError::Json(_))));
    }

    #[test]
    fn rejects_response_bodies_over_the_limit_before_parsing() {
        let error = read_limited(std::io::Cursor::new("12345"), 4).unwrap_err();
        assert!(matches!(error, InventoryError::BodyTooLarge));
    }

    #[test]
    fn round_trips_normalized_inventory_cache() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.json");
        let targets = parse(FIXTURE).unwrap();
        let fetched_at = SystemTime::UNIX_EPOCH + Duration::from_secs(123_456);
        store_cache_to(&path, &targets, fetched_at).unwrap();

        let cached = load_cache_from(&path).unwrap().unwrap();
        assert_eq!(cached.targets, targets);
        assert_eq!(cached.fetched_at, fetched_at);

        let refreshed_at = fetched_at + Duration::from_secs(60);
        store_cache_to(&path, &targets, refreshed_at).unwrap();
        assert_eq!(
            load_cache_from(&path).unwrap().unwrap().fetched_at,
            refreshed_at
        );
    }

    #[test]
    fn missing_inventory_cache_is_not_an_error() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            load_cache_from(&directory.path().join("missing.json"))
                .unwrap()
                .is_none()
        );
    }
}
