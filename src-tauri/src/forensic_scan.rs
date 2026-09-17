//! One metadata walk per mount point. No per-file processes, no line-delimited
//! filenames, no following symlinks or crossing into another mounted filesystem.
use std::{collections::BTreeMap, io::{self, Write}, path::Path, process::{Command, Stdio}, time::{SystemTime, UNIX_EPOCH}};
use super::forensic_directory::Directory;
use serde_json::{json, Value};

const SYSTEM: &[&str] = &[".Spotlight-V100", ".fseventsd", ".TemporaryItems", ".DocumentRevisions-V100", ".Trashes", "$RECYCLE.BIN", "System Volume Information"];
const TOP: usize = 15;
const HELPER_FLAG: &str = "--forensic-directory-scan";

/// Reuse the installed, signed executable, but exit before initializing Tauri.
/// The helper only enumerates metadata and returns JSON; it never opens a UI,
/// reads file contents, changes permissions or writes to the scanned volume.
pub fn helper_exit_code() -> Option<i32> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(HELPER_FLAG)) { return None; }
    let root = args.next().map(std::path::PathBuf::from);
    let result = (|| -> Result<(), String> {
        let root = root.ok_or("Verzeichnis für die Prüfung fehlt")?;
        if args.next().is_some() || !root.is_absolute() {
            return Err("Ungültiger Aufruf der Verzeichnisprüfung".into());
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err("Verzeichnisprüfung benötigt Administrator-Rechte".into());
        }
        serde_json::to_writer(io::stdout().lock(), &scan(&root)).map_err(|e| e.to_string())
    })();
    Some(match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("{error}"); 1 }
    })
}

pub fn scan_privileged(root: &Path, password: &str) -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    scan_with_sudo(root, password, &executable, Path::new("/usr/bin/sudo"))
}

fn scan_with_sudo(root: &Path, password: &str, executable: &Path, sudo: &Path) -> Result<Value, String> {
    if !root.is_absolute() { return Err("Verzeichnisprüfung benötigt einen absoluten Pfad".into()); }
    // No shell interpolation, password in stdin only. -k forces authentication
    // even if an earlier forensic command left a cached sudo credential.
    let mut child = Command::new(sudo)
        .args(["-k", "-S", "-p", "", "--"])
        .arg(executable).arg(HELPER_FLAG).arg(root)
        .current_dir("/")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("Verzeichnisprüfung konnte nicht gestartet werden: {e}"))?;
    if let Some(mut input) = child.stdin.take() {
        // Closing the pipe also terminates a rejected password's re-prompt.
        let _ = writeln!(input, "{password}");
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!("Verzeichnisprüfung mit Administrator-Rechten fehlgeschlagen: {}",
            String::from_utf8_lossy(&output.stderr).trim()));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Ungültiges Ergebnis der Verzeichnisprüfung: {e}"))?;
    if value["scan_quality"]["elevated"] != true || !value["scan_quality"]["complete"].is_boolean() {
        return Err("Bestätigung der erhöhten Rechte für die Verzeichnisprüfung fehlt".into());
    }
    Ok(value)
}

#[derive(Default)]
struct Scan {
    files: u64, dirs: u64, links: u64, items: u64, user_items: u64,
    user_files: u64, user_dirs: u64, hidden: u64,
    largest: Vec<(u64, String)>, recent: Vec<(u64, String)>,
    extensions: BTreeMap<String, u64>, hidden_paths: Vec<String>, roots: Vec<String>,
    errors: Vec<String>, error_count: u64, skipped_mounts: u64, truncated_types: u64,
    permission_denied_count: u64, io_error_count: u64, other_error_count: u64,
}
fn top(items: &mut Vec<(u64, String)>, value: (u64, String)) {
    if items.len() == TOP && items.last().is_some_and(|last| value.0 < last.0 || (value.0 == last.0 && value.1 >= last.1)) { return; }
    items.push(value);
    items.sort_unstable_by(|a,b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    items.truncate(TOP);
}

pub fn filesystem_stats(root: &Path) -> serde_json::Map<String, Value> {
    use std::os::unix::ffi::OsStrExt;
    let mut stats = serde_json::Map::new();
    let Ok(path) = std::ffi::CString::new(root.as_os_str().as_bytes()) else { return stats; };
    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: CString and output pointer are valid for the duration of this call.
    if unsafe { libc::statvfs(path.as_ptr(), raw.as_mut_ptr()) } != 0 { return stats; }
    // SAFETY: statvfs succeeded and initialized the output structure.
    let value = unsafe { raw.assume_init() };
    stats.insert("total_blocks".into(), json!(value.f_blocks));
    stats.insert("free_blocks".into(), json!(value.f_bfree));
    let used = value.f_blocks.saturating_sub(value.f_bfree);
    stats.insert("used_blocks".into(), json!(used));
    if value.f_blocks > 0 { stats.insert("capacity_percent".into(), json!(format!("{:.0}%", used as f64 / value.f_blocks as f64 * 100.0))); }
    if value.f_files > 0 && value.f_ffree <= value.f_files {
        let used = value.f_files - value.f_ffree;
        stats.insert("total_inodes".into(), json!(value.f_files));
        stats.insert("used_inodes".into(), json!(used));
        stats.insert("free_inodes".into(), json!(value.f_ffree));
        stats.insert("inode_usage_percent".into(), json!(format!("{:.0}%", used as f64 / value.f_files as f64 * 100.0)));
    }
    stats
}
impl Scan {
    fn error(&mut self, path: &Path, error: io::Error) {
        self.error_count += 1;
        if error.kind() == io::ErrorKind::PermissionDenied {
            self.permission_denied_count += 1;
        } else if matches!(error.raw_os_error(), Some(libc::EIO | libc::ENXIO | libc::ENODEV)) {
            self.io_error_count += 1;
        } else {
            self.other_error_count += 1;
        }
        if self.errors.len() < 20 { self.errors.push(format!("{}: {error}", path.display())); }
    }
}
pub fn scan(root: &Path) -> Value {
    let mut s = Scan::default();
    let started = std::time::Instant::now();
    let cutoff = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(7*86400);
    let entries = Directory::open(root);
    if let Ok(entries) = entries {
        let device = entries.device;
        let mut stack = vec![(entries, std::path::PathBuf::from("/"), false)];
        while let Some((entries, parent, inherited_system)) = stack.last_mut() {
            let inherited_system = *inherited_system;
            let entry = match entries.next() {
                Some(Ok(e)) => e,
                Some(Err(e)) => { s.error(parent, e); stack.pop(); continue; },
                None => { stack.pop(); continue; }
            };
            let path = parent.join(&entry);
            let name = entry.to_string_lossy();
            let is_system = inherited_system || SYSTEM.iter().any(|v| name.eq_ignore_ascii_case(v));
            let display = path.to_string_lossy().into_owned();
            let metadata = match entries.metadata(&entry) {
                Ok(m) => m, Err(e) => { s.error(Path::new(&display), e); continue; }
            };
            s.items += 1;
            if !is_system { s.user_items += 1; }
            if parent == Path::new("/") && s.roots.len() < 30 { s.roots.push(name.to_string()); }
            let kind = metadata.st_mode & libc::S_IFMT;
            if kind == libc::S_IFLNK { s.links += 1; }
            else if kind == libc::S_IFDIR {
                s.dirs += 1;
                if !is_system { s.user_dirs += 1; }
                if metadata.st_dev as u64 != device { s.skipped_mounts += 1; continue; }
                match entries.child(&entry) {
                    Ok(child) if child.device == device => stack.push((child, path, is_system)),
                    Ok(_) => s.skipped_mounts += 1,
                    Err(e) => s.error(Path::new(&display), e),
                }
            } else if kind == libc::S_IFREG {
                s.files += 1;
                if !is_system { s.user_files += 1; }
                if name.starts_with('.') {
                    s.hidden += 1;
                    if s.hidden_paths.len() < TOP { s.hidden_paths.push(display.clone()); }
                }
                top(&mut s.largest, (metadata.st_size.max(0) as u64, display.clone()));
                let modified = metadata.st_mtime.max(0) as u64;
                if modified >= cutoff { top(&mut s.recent, (modified, display)); }
                let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).filter(|e| !e.is_empty()).unwrap_or_else(|| "(no extension)".into());
                if s.extensions.len() < 4096 || s.extensions.contains_key(&ext) {
                    *s.extensions.entry(ext).or_default() += 1;
                } else { s.truncated_types += 1; }
            }
        }
    } else if let Err(e) = entries { s.error(root, e); }
    let mut types: Vec<_> = s.extensions.into_iter().collect();
    types.sort_by(|a,b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let complete = s.error_count == 0 && s.skipped_mounts == 0;
    json!({
        "total_items":s.items, "user_items":s.user_items,
        "file_count":s.files, "total_file_count":s.files, "user_file_count":s.user_files,
        "directory_count":s.dirs, "user_directory_count":s.user_dirs,
        "symlink_count":s.links, "hidden_files_count":s.hidden, "hidden_files":s.hidden_paths,
        "largest_files":s.largest.into_iter().take(10).map(|(size,path)| json!({"size_bytes":size, "size_human":super::format_bytes(size),"path":path})).collect::<Vec<_>>(),
        "file_type_distribution":types.into_iter().take(TOP).map(|(extension,count)| json!({"extension":extension,"count":count})).collect::<Vec<_>>(),
        "recently_modified":s.recent.into_iter().map(|(_,path)| path).collect::<Vec<_>>(),
        "top_level_items":s.roots,
        "scan_quality":{"complete":complete, "errors":s.errors, "error_count":s.error_count,
            "permission_denied_count":s.permission_denied_count, "io_error_count":s.io_error_count,
            "other_error_count":s.other_error_count,
            "elevated":unsafe { libc::geteuid() } == 0,
            "skipped_mounts":s.skipped_mounts,"max_depth":null,"follows_symlinks":false,
            "type_overflow":s.truncated_types,"list_limit":TOP,"duration_ms":started.elapsed().as_millis()}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn permission_denials_are_separate_from_device_and_other_errors() {
        let mut s = Scan::default();
        for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::ENXIO, libc::ENODEV, libc::ENOENT] {
            s.error(Path::new("/.Trashes"), io::Error::from_raw_os_error(code));
        }
        assert_eq!(s.error_count, 6);
        assert_eq!(s.permission_denied_count, 2);
        assert_eq!(s.io_error_count, 3);
        assert_eq!(s.other_error_count, 1);
        assert!(s.errors.iter().all(|e| e.starts_with("/.Trashes:")));
    }

    #[test]
    fn unreadable_directory_keeps_partial_counts_and_reports_denied_access() {
        let root = tempfile::tempdir().unwrap();
        let protected = root.path().join(".Trashes");
        fs::create_dir(&protected).unwrap();
        fs::write(protected.join("hidden"), b"data").unwrap();
        fs::write(root.path().join("visible"), b"data").unwrap();
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o000)).unwrap();
        let value = scan(root.path());
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(value["scan_quality"]["complete"], true);
            assert_eq!(value["file_count"], 2);
        } else {
            assert_eq!(value["scan_quality"]["complete"], false);
            assert_eq!(value["scan_quality"]["permission_denied_count"], 1);
            assert_eq!(value["scan_quality"]["io_error_count"], 0);
            assert_eq!(value["file_count"], 1);
        }
    }

    fn fake_sudo(dir: &Path, script: &str) -> std::path::PathBuf {
        let path = dir.join("sudo");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn privileged_launch_preserves_paths_and_keeps_password_off_arguments() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("disk ' with\n$(touch SHOULD_NOT_EXIST)");
        let sudo = fake_sudo(temp.path(), r#"
test "$#" -eq 8 || exit 20
test "$1" = -k && test "$2" = -S && test "$3" = -p && test -z "$4" && test "$5" = -- || exit 21
test "$6" = '/application with spaces/app' && test "$7" = --forensic-directory-scan || exit 22
IFS= read -r password
test "$password" = 'test-secret' || exit 23
printf '%s' "$8" > "$0.received-path"
printf '%s' '{"scan_quality":{"complete":true,"elevated":true}}'
"#);
        let value = scan_with_sudo(&root, "test-secret", Path::new("/application with spaces/app"), &sudo).unwrap();
        assert_eq!(value["scan_quality"]["complete"], true);
        assert_eq!(fs::read_to_string(temp.path().join("sudo.received-path")).unwrap(), root.to_str().unwrap());
    }

    #[test]
    fn failed_or_unprivileged_helper_cannot_report_success() {
        let temp = tempfile::tempdir().unwrap();
        for script in [
            "printf '%s' '{\"scan_quality\":{\"complete\":true,\"elevated\":true}}'; exit 1",
            "printf '%s' '{\"scan_quality\":{\"complete\":true,\"elevated\":false}}'",
            "printf '%s' 'not json'",
        ] {
            let sudo = fake_sudo(temp.path(), script);
            assert!(scan_with_sudo(temp.path(), "test-secret", Path::new("/app"), &sudo).is_err());
        }
    }
    #[test]
    fn single_walk_handles_newlines_extensions_and_symlinks() {
        let path = std::env::temp_dir().join(format!("burniso-scan-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join(".fseventsd")).unwrap();
        fs::write(path.join(".fseventsd/log"), b"abc").unwrap();
        fs::write(path.join("a\nb.TXT"), b"123456").unwrap();
        fs::write(path.join("noextension"), b"x").unwrap();
        std::os::unix::fs::symlink(&path, path.join("loop")).unwrap();
        let value = scan(&path);
        assert_eq!(value["total_file_count"], 3);
        assert_eq!(value["user_file_count"], 2);
        assert_eq!(value["directory_count"], 1);
        assert_eq!(value["symlink_count"], 1);
        assert_eq!(value["largest_files"][0]["path"], "/a\nb.TXT");
        assert_eq!(value["scan_quality"]["complete"], true);
        assert!(value["file_type_distribution"].as_array().unwrap().iter().any(|v| v["extension"] == "txt"));
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn missing_mount_is_not_a_successful_empty_scan() {
        let value = scan(Path::new("/nonexistent-burniso-scan"));
        assert_eq!(value["scan_quality"]["complete"], false);
        assert_eq!(value["scan_quality"]["other_error_count"], 1);
    }
}
