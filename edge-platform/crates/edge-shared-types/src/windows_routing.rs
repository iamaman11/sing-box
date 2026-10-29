//! Git-owned application routing. This is routing, not process isolation:
//! children need their own path and Windows shared DNS is system policy.
use crate::{WindowsApplicationRouting, WindowsApplicationScope as Scope, WindowsDefaultRoute};
pub fn validate(policy: Option<&WindowsApplicationRouting>) -> Result<(), &'static str> {
    let Some(policy) = policy else {
        return Ok(());
    };
    let scope = Scope::try_from(policy.scope).map_err(|_| "WINDOWS_APPLICATION_SCOPE_INVALID")?;
    match scope {
        Scope::AllApplications if policy.applications.is_empty() => return Ok(()),
        Scope::SelectedApplications
            if !policy.applications.is_empty() && policy.applications.len() <= 128 => {}
        _ => return Err("WINDOWS_APPLICATION_SCOPE_INVALID"),
    }
    let mut seen = std::collections::BTreeSet::new();
    for app in &policy.applications {
        if app.executable_path.len() > 2048
            || !crate::host_admin::windows_absolute_path(&app.executable_path)
            || !seen.insert(app.executable_path.to_lowercase())
        {
            return Err("WINDOWS_APPLICATION_PATH_INVALID_OR_DUPLICATE");
        }
        if !matches!(WindowsDefaultRoute::try_from(app.route), Ok(route) if route != WindowsDefaultRoute::Unspecified)
        {
            return Err("WINDOWS_APPLICATION_ROUTE_INVALID");
        }
    }
    Ok(())
}

/// Keep the selected executable and each traversed directory non-replaceable
/// through activation. These are routing identities, never programs to run.
/// A successful lexical check alone cannot prove a Windows filesystem path.
#[cfg(windows)]
pub struct NativeApplicationPaths {
    _handles: Vec<std::fs::File>,
}

#[cfg(windows)]
pub fn verify_native_paths(
    policy: Option<&WindowsApplicationRouting>,
) -> Result<NativeApplicationPaths, &'static str> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    validate(policy)?;
    let mut handles = Vec::new();
    if let Some(policy) = policy {
        for app in &policy.applications {
            let path = Path::new(&app.executable_path);
            let mut chain: Vec<_> = path.ancestors().collect();
            chain.reverse();
            for entry in chain {
                let leaf = entry == path;
                let handle = OpenOptions::new()
                    // GENERIC_READ is required for Windows share-mode locking;
                    // attribute-only handles do not exclude rename/write. No
                    // content is read: only handle metadata is inspected.
                    .access_mode(0x80000000)
                    // Directories remain usable, but neither directories nor
                    // the selected file may be replaced while this guard lives.
                    .share_mode(if leaf { 1 } else { 1 | 2 })
                    // FILE_FLAG_OPEN_REPARSE_POINT | BACKUP_SEMANTICS.
                    .custom_flags(0x00200000 | 0x02000000)
                    .open(entry)
                    .map_err(|_| "WINDOWS_APPLICATION_PATH_UNAVAILABLE_OR_BUSY")?;
                let meta = handle
                    .metadata()
                    .map_err(|_| "WINDOWS_APPLICATION_PATH_METADATA_UNPROVEN")?;
                if meta.file_attributes() & 0x400 != 0
                    || (leaf && !meta.is_file())
                    || (!leaf && !meta.is_dir())
                {
                    return Err("WINDOWS_APPLICATION_PATH_REPARSE_OR_TYPE_INVALID");
                }
                handles.push(handle);
            }
            let canonical = path
                .canonicalize()
                .map_err(|_| "WINDOWS_APPLICATION_CANONICAL_PATH_UNPROVEN")?;
            let canonical = canonical
                .to_str()
                .ok_or("WINDOWS_APPLICATION_CANONICAL_PATH_UNPROVEN")?;
            let canonical = canonical.strip_prefix(r"\\?\").unwrap_or(canonical);
            if !canonical.eq_ignore_ascii_case(&app.executable_path) {
                return Err("WINDOWS_APPLICATION_CANONICAL_PATH_MISMATCH");
            }
        }
    }
    Ok(NativeApplicationPaths { _handles: handles })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::WindowsApplicationRoute;
    #[test]
    fn selected_apps_validate_canonical_windows_paths() {
        assert!(validate(None).is_ok());
        let app = WindowsApplicationRoute {
            executable_path: r"C:\Apps\Browser.exe".into(),
            route: WindowsDefaultRoute::AutoDirect as i32,
        };
        let mut p = WindowsApplicationRouting {
            scope: Scope::SelectedApplications as i32,
            applications: vec![app.clone()],
        };
        assert!(validate(Some(&p)).is_ok());
        let mut duplicate = app.clone();
        duplicate.executable_path = app.executable_path.to_uppercase();
        p.applications.push(duplicate);
        assert!(validate(Some(&p)).is_err());
        p.applications.pop();
        for path in [
            "",
            r"browser.exe",
            r"C:\Apps\*.exe",
            r"\\server\app.exe",
            r"C:\a\..\b.exe",
        ] {
            p.applications[0].executable_path = path.into();
            assert!(validate(Some(&p)).is_err());
        }
        p.applications.clear();
        assert!(validate(Some(&p)).is_err());
        p.scope = Scope::AllApplications as i32;
        assert!(validate(Some(&p)).is_ok());
        p.applications.push(app);
        assert!(validate(Some(&p)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn selected_application_identity_is_native_and_locked_until_activation() {
        let root = std::env::temp_dir().join(format!(
            "edge-routing-paths-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        // A Windows CI runner may expose TEMP through a lexical alias
        // (including a short name). Use the actual canonical native path
        // for this positive fixture; the negative junction fixture below
        // still proves that replacement/alias paths are rejected.
        let resolved = root.canonicalize().unwrap();
        let resolved = resolved.to_str().unwrap();
        let root = std::path::PathBuf::from(
            resolved.strip_prefix(r"\\?\").unwrap_or(resolved),
        );
        let path = root.join("selected.exe");
        std::fs::write(&path, b"synthetic routing identity, never executed").unwrap();
        let mut policy = WindowsApplicationRouting {
            scope: Scope::SelectedApplications as i32,
            applications: vec![WindowsApplicationRoute {
                executable_path: path.to_str().unwrap().into(),
                route: WindowsDefaultRoute::AutoDirect as i32,
            }],
        };
        let guard = verify_native_paths(Some(&policy)).unwrap();
        assert!(std::fs::rename(&path, root.join("replaced.exe")).is_err());
        assert!(std::fs::write(&path, b"replaced").is_err());
        assert!(std::fs::rename(&root, root.with_extension("replaced")).is_err());
        drop(guard);
        std::fs::write(&path, b"released").unwrap();
        policy.applications[0].executable_path = root.to_str().unwrap().into();
        assert!(matches!(
            verify_native_paths(Some(&policy)),
            Err("WINDOWS_APPLICATION_PATH_REPARSE_OR_TYPE_INVALID")
        ));
        policy.applications[0].executable_path = root.join("missing.exe").to_str().unwrap().into();
        assert!(matches!(
            verify_native_paths(Some(&policy)),
            Err("WINDOWS_APPLICATION_PATH_UNAVAILABLE_OR_BUSY")
        ));
        // NTFS directory junctions need no symlink privilege. The selected
        // leaf is a regular file, but its intermediate alias must be denied.
        let target = root.join("target");
        let alias = root.join("alias");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("selected.exe"), b"never executed").unwrap();
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new(
            std::path::Path::new(&std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("cmd.exe"),
        )
        // cmd built-ins do not use CRT argv quoting. These fixture paths
        // are below a validated Windows path, with no quote/control bytes.
        .raw_arg(format!(
            r#"/d /c mklink /J "{}" "{}""#,
            alias.display(),
            target.display()
        ))
        .creation_flags(0x08000000)
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "NTFS junction fixture unavailable: {:?} {} {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        policy.applications[0].executable_path =
            alias.join("selected.exe").to_str().unwrap().into();
        assert!(matches!(
            verify_native_paths(Some(&policy)),
            Err("WINDOWS_APPLICATION_PATH_REPARSE_OR_TYPE_INVALID")
        ));
        std::fs::remove_dir(alias).unwrap();
        std::fs::remove_file(target.join("selected.exe")).unwrap();
        std::fs::remove_dir(target).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
