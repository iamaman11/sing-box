use edge_secrets::{ACCESS_IDENTITY_FILE_NAME, write_access_service_identity};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const ACCESS_BOOTSTRAP_PUBLIC_CERT_FILE: &str = "credential-access-bootstrap.cer";
const ACCESS_BOOTSTRAP_CMS_FILE: &str = "credential-access-bootstrap.cms";
const ACCESS_BOOTSTRAP_THUMBPRINT_FILE: &str = "credential-access-bootstrap-thumbprint.txt";
const ACCESS_BOOTSTRAP_PLAINTEXT_FILE: &str = "credential-access-bootstrap.plain";

fn public_cert_path(install_root: &Path) -> PathBuf {
    install_root
        .join("exchange")
        .join("results")
        .join(ACCESS_BOOTSTRAP_PUBLIC_CERT_FILE)
}

fn cms_path(install_root: &Path) -> PathBuf {
    install_root
        .join("exchange")
        .join("requests")
        .join(ACCESS_BOOTSTRAP_CMS_FILE)
}

fn thumbprint_path(install_root: &Path) -> PathBuf {
    install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_BOOTSTRAP_THUMBPRINT_FILE)
}

fn plaintext_path(install_root: &Path) -> PathBuf {
    install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_BOOTSTRAP_PLAINTEXT_FILE)
}

fn identity_path(install_root: &Path) -> PathBuf {
    install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME)
}

pub(crate) fn prepare(install_root: &Path) -> Result<(String, String, Option<String>), String> {
    #[cfg(not(windows))]
    {
        let _ = install_root;
        Err("credential Access bootstrap preparation is Windows-only".to_owned())
    }

    #[cfg(windows)]
    {
        let public_cert = public_cert_path(install_root);
        let thumbprint = thumbprint_path(install_root);
        let script = r#"
$ErrorActionPreference = 'Stop'
$subject = 'CN=sing-box-credential-access-bootstrap'
$publicCert = $env:EDGE_ACCESS_BOOTSTRAP_PUBLIC_CERT
$thumbprintPath = $env:EDGE_ACCESS_BOOTSTRAP_THUMBPRINT
if (Test-Path -LiteralPath $thumbprintPath -PathType Leaf) {
    $thumb = (Get-Content -LiteralPath $thumbprintPath -Raw).Trim()
    if ($thumb -notmatch '^[0-9A-Fa-f]{40}$') { throw 'stored bootstrap certificate thumbprint is malformed' }
    $cert = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $thumb) -ErrorAction SilentlyContinue
    if (-not $cert) { throw 'stored bootstrap certificate is missing from LocalMachine store' }
    $cert | Export-Certificate -FilePath $publicCert -Force | Out-Null
    exit 0
}
$existing = @(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -ceq $subject })
if ($existing.Count -ne 0) { throw 'unexpected pre-existing bootstrap certificate' }
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'sing-box-credential-access-bootstrap' -CertStoreLocation 'Cert:\LocalMachine\My' -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddHours(2)
$cert | Export-Certificate -FilePath $publicCert -Force | Out-Null
[IO.File]::WriteAllText($thumbprintPath, $cert.Thumbprint, [Text.UTF8Encoding]::new($false))
"#;
        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .env("EDGE_ACCESS_BOOTSTRAP_PUBLIC_CERT", &public_cert)
            .env("EDGE_ACCESS_BOOTSTRAP_THUMBPRINT", &thumbprint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("failed to prepare Windows CMS bootstrap recipient: {err}"))?;
        if !status.success() {
            return Err(format!(
                "Windows CMS bootstrap recipient preparation failed with exit code {}",
                status.code().unwrap_or(-1)
            ));
        }

        let metadata = fs::metadata(&public_cert)
            .map_err(|err| format!("bootstrap public certificate is missing: {err}"))?;
        if metadata.len() == 0 || metadata.len() > 64 * 1024 {
            return Err("bootstrap public certificate size is invalid".to_owned());
        }

        Ok((
            "CREDENTIAL_ACCESS_BOOTSTRAP_PREPARED".to_owned(),
            format!("public certificate ready at {}", public_cert.display()),
            None,
        ))
    }
}

pub(crate) fn install(install_root: &Path) -> Result<(String, String, Option<String>), String> {
    #[cfg(not(windows))]
    {
        let _ = install_root;
        Err("credential Access bootstrap installation is Windows-only".to_owned())
    }

    #[cfg(windows)]
    {
        let cms = cms_path(install_root);
        let thumbprint = thumbprint_path(install_root);
        let plaintext = plaintext_path(install_root);
        let identity = identity_path(install_root);
        if !cms.is_file() {
            return Err("credential Access bootstrap CMS envelope is missing".to_owned());
        }

        let decrypt_script = r#"
$ErrorActionPreference = 'Stop'
$cmsPath = $env:EDGE_ACCESS_BOOTSTRAP_CMS
$thumbprintPath = $env:EDGE_ACCESS_BOOTSTRAP_THUMBPRINT
$plaintextPath = $env:EDGE_ACCESS_BOOTSTRAP_PLAINTEXT
$thumb = (Get-Content -LiteralPath $thumbprintPath -Raw).Trim()
if ($thumb -notmatch '^[0-9A-Fa-f]{40}$') { throw 'stored bootstrap certificate thumbprint is malformed' }
$cert = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $thumb) -ErrorAction Stop
$plain = Unprotect-CmsMessage -LiteralPath $cmsPath -To $cert
if ([string]::IsNullOrWhiteSpace([string]$plain)) { throw 'CMS bootstrap envelope decrypted to empty content' }
[IO.File]::WriteAllText($plaintextPath, [string]$plain, [Text.UTF8Encoding]::new($false))
"#;
        let decrypt_status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                decrypt_script,
            ])
            .env("EDGE_ACCESS_BOOTSTRAP_CMS", &cms)
            .env("EDGE_ACCESS_BOOTSTRAP_THUMBPRINT", &thumbprint)
            .env("EDGE_ACCESS_BOOTSTRAP_PLAINTEXT", &plaintext)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("failed to decrypt Windows CMS bootstrap envelope: {err}"))?;
        if !decrypt_status.success() {
            return Err(format!(
                "Windows CMS bootstrap decryption failed with exit code {}",
                decrypt_status.code().unwrap_or(-1)
            ));
        }

        let raw = fs::read_to_string(&plaintext)
            .map_err(|err| format!("failed to read protected bootstrap plaintext: {err}"))?;
        let install_result = write_access_service_identity(&identity, &raw);
        let _ = fs::remove_file(&plaintext);
        install_result?;

        let cleanup_script = r#"
$ErrorActionPreference = 'Stop'
$thumbprintPath = $env:EDGE_ACCESS_BOOTSTRAP_THUMBPRINT
$thumb = (Get-Content -LiteralPath $thumbprintPath -Raw).Trim()
Remove-Item -LiteralPath ("Cert:\LocalMachine\My\" + $thumb) -Force -ErrorAction Stop
"#;
        let cleanup_status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                cleanup_script,
            ])
            .env("EDGE_ACCESS_BOOTSTRAP_THUMBPRINT", &thumbprint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("failed to remove Windows bootstrap certificate: {err}"))?;
        if !cleanup_status.success() {
            return Err(format!(
                "credential Access identity installed but bootstrap certificate cleanup failed with exit code {}",
                cleanup_status.code().unwrap_or(-1)
            ));
        }

        let _ = fs::remove_file(&thumbprint);
        let _ = fs::remove_file(public_cert_path(install_root));
        let _ = fs::remove_file(&cms);

        Ok((
            "CREDENTIAL_ACCESS_IDENTITY_INSTALLED".to_owned(),
            "credential Access host identity installed under controller-owned ACLs; bootstrap key destroyed".to_owned(),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_paths_stay_inside_existing_ownership_roots() {
        let root = Path::new(r"C:\sing-box");
        assert!(public_cert_path(root).ends_with(ACCESS_BOOTSTRAP_PUBLIC_CERT_FILE));
        assert!(cms_path(root).ends_with(ACCESS_BOOTSTRAP_CMS_FILE));
        assert!(thumbprint_path(root).ends_with(ACCESS_BOOTSTRAP_THUMBPRINT_FILE));
        assert!(plaintext_path(root).ends_with(ACCESS_BOOTSTRAP_PLAINTEXT_FILE));
        assert!(identity_path(root).ends_with(ACCESS_IDENTITY_FILE_NAME));
    }
}
