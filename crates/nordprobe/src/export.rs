use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::inventory::NordTarget;
use crate::key::RunIdentity;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("export cancelled")]
    Cancelled,
    #[error("export cancelled but could not remove {path}: {source}")]
    CancelledCleanup {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the confirmed result belongs to a different client identity")]
    IdentityMismatch,
    #[error("export directory {0} must not be a symbolic link")]
    SymlinkDirectory(PathBuf),
    #[error("could not create export directory {path}: {source}")]
    Directory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not write export {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "could not write export {path}: {write_error}; cleanup failed: {cleanup_error}; sensitive partial file containing private-key material remains"
    )]
    SensitivePartialFile {
        path: PathBuf,
        write_error: std::io::Error,
        cleanup_error: std::io::Error,
    },
}

pub fn export(
    identity: &RunIdentity,
    expected_public_key: &str,
    target: &NordTarget,
    directory: &Path,
) -> Result<PathBuf, ExportError> {
    export_to(identity, expected_public_key, target, directory, &|| false)
}

pub fn export_interruptible(
    identity: &RunIdentity,
    expected_public_key: &str,
    target: &NordTarget,
    directory: &Path,
    interrupted: &AtomicBool,
) -> Result<PathBuf, ExportError> {
    export_to(identity, expected_public_key, target, directory, &|| {
        interrupted.load(Ordering::Acquire)
    })
}

fn export_to(
    identity: &RunIdentity,
    expected_public_key: &str,
    target: &NordTarget,
    root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<PathBuf, ExportError> {
    if cancelled() {
        return Err(ExportError::Cancelled);
    }
    if identity.public_key() != expected_public_key {
        return Err(ExportError::IdentityMismatch);
    }
    ensure_directory(root)?;
    if cancelled() {
        return Err(ExportError::Cancelled);
    }
    let directory = root;

    let stem = sanitize_hostname(&target.hostname);
    for suffix in 0..10_000u32 {
        let filename = if suffix == 0 {
            format!("{stem}.conf")
        } else {
            format!("{stem}-{suffix}.conf")
        };
        let path = directory.join(filename);
        if cancelled() {
            return Err(ExportError::Cancelled);
        }
        match secure_create(&path) {
            Ok(file) => {
                let config = Zeroizing::new(format!(
                    "[Interface]\nPrivateKey = {}\nAddress = 10.5.0.2/32\nDNS = 103.86.96.100,103.86.99.100\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}\nPersistentKeepalive = 25\n",
                    identity.private_key(),
                    target.public_key,
                    target.endpoint
                ));
                if cancelled() {
                    drop(file);
                    return Err(cancelled_export(&path));
                }
                write_sensitive_config(file, config.as_bytes(), &path, |path| {
                    fs::remove_file(path)
                })?;
                if cancelled() {
                    return Err(cancelled_export(&path));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(ExportError::Write { path, source }),
        }
    }
    Err(ExportError::Write {
        path: directory.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "no unused export filename was available",
        ),
    })
}

fn cancelled_export(path: &Path) -> ExportError {
    cleanup_partial(path, ExportFailure::Cancelled, |path| fs::remove_file(path))
}

fn write_sensitive_config<W, R>(
    mut writer: W,
    config: &[u8],
    path: &Path,
    remove_file: R,
) -> Result<(), ExportError>
where
    W: Write,
    R: FnOnce(&Path) -> std::io::Result<()>,
{
    if let Err(source) = writer.write_all(config) {
        drop(writer);
        return Err(cleanup_partial(
            path,
            ExportFailure::Write(source),
            remove_file,
        ));
    }
    Ok(())
}

enum ExportFailure {
    Cancelled,
    Write(std::io::Error),
}

fn cleanup_partial<R>(path: &Path, failure: ExportFailure, remove_file: R) -> ExportError
where
    R: FnOnce(&Path) -> std::io::Result<()>,
{
    match (failure, remove_file(path)) {
        (ExportFailure::Cancelled, Ok(())) => ExportError::Cancelled,
        (ExportFailure::Cancelled, Err(source)) => ExportError::CancelledCleanup {
            path: path.to_owned(),
            source,
        },
        (ExportFailure::Write(source), Ok(())) => ExportError::Write {
            path: path.to_owned(),
            source,
        },
        (ExportFailure::Write(write_error), Err(cleanup_error)) => {
            ExportError::SensitivePartialFile {
                path: path.to_owned(),
                write_error,
                cleanup_error,
            }
        }
    }
}

fn ensure_directory(path: &Path) -> Result<(), ExportError> {
    reject_symlink_components(path)?;
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ExportError::SymlinkDirectory(path.to_owned()));
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(ExportError::Directory {
                path: path.to_owned(),
                source,
            });
        }
    };
    let created = if existed {
        false
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ExportError::Directory {
                path: parent.to_owned(),
                source,
            })?;
            reject_symlink_components(parent)?;
        }
        match fs::create_dir(path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(source) => {
                return Err(ExportError::Directory {
                    path: path.to_owned(),
                    source,
                });
            }
        }
    };
    let metadata = fs::symlink_metadata(path).map_err(|source| ExportError::Directory {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ExportError::SymlinkDirectory(path.to_owned()));
    }
    if !metadata.file_type().is_dir() {
        return Err(ExportError::Directory {
            path: path.to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "export path is not a directory",
            ),
        });
    }
    if !created {
        Ok(())
    } else {
        restrict_directory(path).map_err(|source| ExportError::Directory {
            path: path.to_owned(),
            source,
        })
    }
}

fn reject_symlink_components(path: &Path) -> Result<(), ExportError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ExportError::SymlinkDirectory(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(ExportError::Directory {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn sanitize_hostname(hostname: &str) -> String {
    let value: String = hostname
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let value = value.trim_matches('.');
    if value.is_empty() {
        "nord-server"
    } else {
        value
    }
    .to_owned()
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn secure_create(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::SocketAddr;

    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn target() -> NordTarget {
        NordTarget {
            name: "Test".into(),
            hostname: "../bad host".into(),
            endpoint: "192.0.2.1:51820".parse::<SocketAddr>().unwrap(),
            public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            country: "Test".into(),
            city: "Test".into(),
            load: 1,
        }
    }

    struct FailingWriter {
        file: fs::File,
        bytes_before_failure: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.bytes_before_failure == 0 {
                return Err(io::Error::other("injected write failure"));
            }
            let length = buffer.len().min(self.bytes_before_failure);
            let written = self.file.write(&buffer[..length])?;
            self.bytes_before_failure -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    #[test]
    fn rejects_identity_mismatch_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let identity = RunIdentity::parse(KEY).unwrap();
        let error = export_to(&identity, "different", &target(), directory.path(), &|| {
            false
        })
        .unwrap_err();
        assert!(matches!(error, ExportError::IdentityMismatch));
        assert!(!directory.path().join("exports").exists());
    }

    #[test]
    fn creates_unique_restrictive_exports_without_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path())
            .unwrap()
            .join("nordprobe-exports");
        let identity = RunIdentity::parse(KEY).unwrap();
        let first = export_to(&identity, identity.public_key(), &target(), &root, &|| {
            false
        })
        .unwrap();
        let second = export_to(&identity, identity.public_key(), &target(), &root, &|| {
            false
        })
        .unwrap();
        assert_ne!(first, second);
        assert_eq!(first.file_name().unwrap(), "_bad_host.conf");
        assert_eq!(second.file_name().unwrap(), "_bad_host-1.conf");
        assert!(fs::read_to_string(&first).unwrap().contains(KEY));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(first).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn preserves_permissions_on_existing_export_directory() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap().join("existing");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let identity = RunIdentity::parse(KEY).unwrap();

        export_to(&identity, identity.public_key(), &target(), &root, &|| {
            false
        })
        .unwrap();

        assert_eq!(
            fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_managed_directory() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(directory.path()).unwrap();
        let destination = base.join("destination");
        fs::create_dir(&destination).unwrap();
        let root = base.join("nordprobe");
        symlink(&destination, &root).unwrap();
        let identity = RunIdentity::parse(KEY).unwrap();
        let error = export_to(&identity, identity.public_key(), &target(), &root, &|| {
            false
        })
        .unwrap_err();
        assert!(matches!(error, ExportError::SymlinkDirectory(path) if path == root));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_export_directory_ancestor() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(directory.path()).unwrap();
        let destination = base.join("destination");
        fs::create_dir(&destination).unwrap();
        let link = base.join("link");
        symlink(&destination, &link).unwrap();
        let root = link.join("nested-export");
        let identity = RunIdentity::parse(KEY).unwrap();

        let error = export_to(&identity, identity.public_key(), &target(), &root, &|| {
            false
        })
        .unwrap_err();

        assert!(matches!(error, ExportError::SymlinkDirectory(path) if path == link));
        assert!(!destination.join("nested-export").exists());
    }

    #[test]
    fn cancelled_export_does_not_create_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("cancelled");
        let identity = RunIdentity::parse(KEY).unwrap();
        let interrupted = AtomicBool::new(true);

        let error = export_interruptible(
            &identity,
            identity.public_key(),
            &target(),
            &root,
            &interrupted,
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::Cancelled));
        assert!(!root.exists());
    }

    #[test]
    fn write_failure_removes_sensitive_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.conf");
        let writer = FailingWriter {
            file: secure_create(&path).unwrap(),
            bytes_before_failure: 4,
        };

        let error =
            write_sensitive_config(writer, b"private-key", &path, |path| fs::remove_file(path))
                .unwrap_err();

        assert!(matches!(error, ExportError::Write { .. }));
        assert!(!path.exists());
    }

    #[test]
    fn write_failure_reports_sensitive_partial_file_when_cleanup_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.conf");
        let writer = FailingWriter {
            file: secure_create(&path).unwrap(),
            bytes_before_failure: 4,
        };

        let error = write_sensitive_config(writer, b"private-key", &path, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected cleanup failure",
            ))
        })
        .unwrap_err();

        assert!(matches!(error, ExportError::SensitivePartialFile { .. }));
        assert!(error.to_string().contains("sensitive partial file"));
        assert!(path.exists());
    }
}
