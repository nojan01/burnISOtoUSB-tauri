//! One metadata walk per mount point. No per-file processes, no line-delimited
//! filenames, no following symlinks or crossing into another mounted filesystem.
use std::{collections::BTreeMap, fs, path::Path, time::{SystemTime, UNIX_EPOCH}};
use std::os::unix::fs::MetadataExt;
use serde_json::{json, Value};

const SYSTEM: &[&str] = &[".Spotlight-V100", ".fseventsd", ".TemporaryItems", ".DocumentRevisions-V100", ".Trashes", "$RECYCLE.BIN", "System Volume Information"];
const TOP: usize = 15;

#[derive(Default)]
struct Scan {
    files: u64, dirs: u64, links: u64, items: u64, user_items: u64,
    user_files: u64, user_dirs: u64, hidden: u64,
    largest: Vec<(u64, String)>, recent: Vec<(u64, String)>,
    extensions: BTreeMap<String, u64>, hidden_paths: Vec<String>, roots: Vec<String>,
    errors: Vec<String>, error_count: u64, skipped_mounts: u64, truncated_types: u64,
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
    fn error(&mut self, error: impl ToString) {
        self.error_count += 1;
        if self.errors.len() < 20 { self.errors.push(error.to_string()); }
    }
}
pub fn scan(root: &Path) -> Value {
    let mut s = Scan::default();
    let started = std::time::Instant::now();
    let cutoff = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(7*86400);
    let device = fs::metadata(root).map(|m| m.dev());
    if let (Ok(device), Ok(entries)) = (device, fs::read_dir(root)) {
        let mut stack = vec![(entries, false)];
        while let Some((entries, inherited_system)) = stack.last_mut() {
            let inherited_system = *inherited_system;
            let entry = match entries.next() {
                Some(Ok(e)) => e,
                Some(Err(e)) => { s.error(e); continue; },
                None => { stack.pop(); continue; }
            };
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_system = inherited_system || SYSTEM.iter().any(|v| name.eq_ignore_ascii_case(v));
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let display = format!("/{}", relative.to_string_lossy());
            let metadata = match fs::symlink_metadata(&path) {
                Ok(m) => m, Err(e) => { s.error(format!("{}: {e}", display)); continue; }
            };
            s.items += 1;
            if !is_system { s.user_items += 1; }
            if stack.len() == 1 && s.roots.len() < 30 { s.roots.push(name.to_string()); }
            if metadata.is_symlink() { s.links += 1; }
            else if metadata.is_dir() {
                s.dirs += 1;
                if !is_system { s.user_dirs += 1; }
                if metadata.dev() != device { s.skipped_mounts += 1; continue; }
                match fs::read_dir(&path) {
                    Ok(entries) => stack.push((entries, is_system)),
                    Err(e) => s.error(format!("{}: {e}", display)),
                }
            } else if metadata.is_file() {
                s.files += 1;
                if !is_system { s.user_files += 1; }
                if name.starts_with('.') {
                    s.hidden += 1;
                    if s.hidden_paths.len() < TOP { s.hidden_paths.push(display.clone()); }
                }
                top(&mut s.largest, (metadata.len(), display.clone()));
                let modified = metadata.mtime().max(0) as u64;
                if modified >= cutoff { top(&mut s.recent, (modified, display)); }
                let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).filter(|e| !e.is_empty()).unwrap_or_else(|| "(no extension)".into());
                if s.extensions.len() < 4096 || s.extensions.contains_key(&ext) {
                    *s.extensions.entry(ext).or_default() += 1;
                } else { s.truncated_types += 1; }
            }
        }
    } else { s.error(format!("Verzeichnis nicht lesbar: {}", root.display())); }
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
            "skipped_mounts":s.skipped_mounts,"max_depth":null,"follows_symlinks":false,
            "type_overflow":s.truncated_types,"list_limit":TOP,"duration_ms":started.elapsed().as_millis()}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(scan(Path::new("/nonexistent-burniso-scan"))["scan_quality"]["complete"], false);
    }
}
