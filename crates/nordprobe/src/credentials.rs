use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

const CREDENTIALS_URL: &str = "https://api.nordvpn.com/v1/users/services/credentials";
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const LOCK_INDICATOR: char = '🔒';
const LOCK_INDICATOR_BYTES: &[u8] = "🔒".as_bytes();

struct SingleLockWriter<W> {
    inner: W,
    prompt_written: bool,
    lock_written: bool,
}

impl<W> SingleLockWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            prompt_written: false,
            lock_written: false,
        }
    }
}

impl<W: Write> Write for SingleLockWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.prompt_written && buffer == LOCK_INDICATOR_BYTES {
            if !self.lock_written {
                self.inner.write_all(buffer)?;
                self.lock_written = true;
            }
            return Ok(buffer.len());
        }

        let mut erase_chunks = buffer.chunks_exact(3);
        if self.prompt_written
            && !buffer.is_empty()
            && erase_chunks.by_ref().all(|chunk| chunk == b"\x08 \x08")
            && erase_chunks.remainder().is_empty()
        {
            return Ok(buffer.len());
        }

        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()?;
        self.prompt_written = true;
        Ok(())
    }
}

#[derive(Deserialize)]
struct CredentialResponse {
    nordlynx_private_key: String,
}

pub fn fetch_to(output: &Path) -> Result<PathBuf, String> {
    ensure_secure_file_creation()?;
    let token = Zeroizing::new(prompt_access_token()?);
    validate_access_token(&token)?;

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("could not create Nord credential client: {error}"))?;
    let request = credential_request(&client, &token);
    drop(token);
    let response = request
        .send()
        .map_err(|error| format!("Nord credential request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Nord credential request returned HTTP {}",
            response.status()
        ));
    }

    let mut body = Zeroizing::new(Vec::new());
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("could not read Nord credential response: {error}"))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Nord credential response exceeded the size limit".into());
    }
    let mut returned_key = parse_credential_response(&body)?;
    body.zeroize();
    let key = normalize_private_key(&returned_key)?;
    returned_key.zeroize();
    write_private_key(output, &key)?;
    Ok(output.to_owned())
}

fn prompt_access_token() -> Result<String, String> {
    let terminal = OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|error| format!("could not open terminal for access-token prompt: {error}"))?;
    let config = rpassword::ConfigBuilder::new()
        .output_writer(SingleLockWriter::new(terminal))
        .password_feedback_mask(LOCK_INDICATOR)
        .build();
    rpassword::prompt_password_with_config("Nord access token: ", config)
        .map_err(|error| format!("could not read hidden access token: {error}"))
}

fn ensure_secure_file_creation() -> Result<(), String> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err("native key retrieval currently requires Unix mode-0600 file creation".into())
    }
}

fn credential_request(
    client: &reqwest::blocking::Client,
    token: &str,
) -> reqwest::blocking::RequestBuilder {
    client.get(CREDENTIALS_URL).basic_auth("token", Some(token))
}

fn parse_credential_response(body: &[u8]) -> Result<Zeroizing<String>, String> {
    let document: CredentialResponse = serde_json::from_slice(body)
        .map_err(|_| "Nord returned an invalid credential response".to_owned())?;
    Ok(Zeroizing::new(document.nordlynx_private_key))
}

fn validate_access_token(token: &str) -> Result<(), String> {
    if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("the Nord access token must contain 64 hexadecimal characters".into())
    }
}

fn normalize_private_key(value: &str) -> Result<Zeroizing<String>, String> {
    let mut decoded = Zeroizing::new([0u8; 32]);
    if STANDARD
        .decode_slice(value, decoded.as_mut())
        .is_ok_and(|length| length == decoded.len())
        && STANDARD.encode(decoded.as_ref()) == value
    {
        return Ok(Zeroizing::new(value.to_owned()));
    }

    decoded.zeroize();
    if value.len() != 64 {
        return Err("Nord returned an invalid NordLynx private key".into());
    }
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(Zeroizing::new(STANDARD.encode(decoded.as_ref())))
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("Nord returned an invalid NordLynx private key".into()),
    }
}

fn write_private_key(path: &Path, key: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "could not create private-key file {}: {error}",
            path.display()
        )
    })?;
    if let Err(error) = file
        .write_all(key.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
    {
        drop(file);
        return match fs::remove_file(path) {
            Ok(()) => Err(format!(
                "could not write private-key file {}: {error}",
                path.display()
            )),
            Err(cleanup_error) => Err(format!(
                "private-key write failed and sensitive partial file {} could not be removed: {cleanup_error}",
                path.display()
            )),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn validates_token_and_normalizes_key_encodings() {
        assert!(validate_access_token(&"a".repeat(64)).is_ok());
        assert!(validate_access_token("not-a-token").is_err());
        assert_eq!(normalize_private_key(KEY).unwrap().as_str(), KEY);
        assert_eq!(
            normalize_private_key(&"0".repeat(64)).unwrap().as_str(),
            KEY
        );
        assert!(normalize_private_key("invalid").is_err());
        assert_eq!(
            parse_credential_response(
                br#"{"nordlynx_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#
            )
            .unwrap()
            .as_str(),
            KEY
        );
        assert!(parse_credential_response(b"null").is_err());
        assert!(parse_credential_response(br#"{"username":"missing-key"}"#).is_err());
    }

    #[test]
    fn builds_fixed_sensitive_credential_request() {
        let request = credential_request(&reqwest::blocking::Client::new(), &"a".repeat(64))
            .build()
            .unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
        assert_eq!(request.url().as_str(), CREDENTIALS_URL);
        let authorization = request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .unwrap();
        assert!(authorization.is_sensitive());
    }

    #[test]
    fn password_feedback_shows_one_lock_without_revealing_length() {
        let mut writer = SingleLockWriter::new(Vec::new());
        writer.write_all(b"Nord access token: ").unwrap();
        writer.flush().unwrap();
        for _ in 0..64 {
            writer.write_all(LOCK_INDICATOR_BYTES).unwrap();
        }
        writer.write_all(b"\x08 \x08").unwrap();
        writer.write_all(b"\x08 \x08\x08 \x08").unwrap();
        writer.write_all(b"\n").unwrap();

        assert_eq!(
            String::from_utf8(writer.inner).unwrap(),
            "Nord access token: 🔒\n"
        );
    }

    #[test]
    fn writes_restrictive_key_without_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private-key");
        write_private_key(&path, KEY).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{KEY}\n"));
        assert!(
            write_private_key(&path, KEY)
                .unwrap_err()
                .contains("could not create")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
