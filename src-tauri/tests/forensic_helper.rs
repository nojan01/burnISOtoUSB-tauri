//! Exercise the real binary's headless entry point (never starts the Tauri UI).
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn helper_requires_root_and_reads_protected_metadata_when_elevated() {
    let fixture = tempfile::tempdir().unwrap();
    let protected = fixture.path().join(".Trashes");
    fs::create_dir(&protected).unwrap();
    fs::write(protected.join("evidence.txt"), b"untouched").unwrap();
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o000)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_burniso-usb"))
        .arg("--forensic-directory-scan").arg(fixture.path()).output().unwrap();
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["scan_quality"]["elevated"], true);
        assert_eq!(value["scan_quality"]["complete"], true);
        assert_eq!(value["file_count"], 1);
    } else {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Administrator-Rechte"));
    }
    assert_eq!(fs::read(protected.join("evidence.txt")).unwrap(), b"untouched");
}

#[test]
fn helper_rejects_missing_relative_and_extra_arguments() {
    for args in [vec![], vec!["relative"], vec!["/tmp", "unexpected"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_burniso-usb"))
            .arg("--forensic-directory-scan").args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
