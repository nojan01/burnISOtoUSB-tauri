//! Exercise the macOS updater's actual tar::Entry::unpack path, not BSD tar.
use std::{fs, path::{Component, Path, PathBuf}};
use flate2::read::GzDecoder;

fn unpack(archive: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut tar = tar::Archive::new(GzDecoder::new(fs::File::open(archive)?));
    let mut root = None;
    let mut count = 0;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.components().any(|c| !matches!(c, Component::Normal(_))) ||
            path.iter().any(|c| c.to_string_lossy().starts_with("._")) {
            return Err(format!("Unsafe/AppleDouble archive member: {}", path.display()).into());
        }
        let top = path.iter().next().ok_or("Empty archive member")?;
        if !top.to_string_lossy().ends_with(".app") { return Err("Archive root is not an app".into()); }
        if root.as_ref().is_some_and(|r| r != top) { return Err("Multiple archive roots".into()); }
        root = Some(top.to_os_string());
        let relative: PathBuf = path.iter().skip(1).collect();
        if entry.header().entry_type().is_symlink() {
            let link = entry.link_name()?.ok_or("Symlink target missing")?;
            let mut depth = relative.parent().map(|p| p.components().count()).unwrap_or(0);
            for component in link.components() {
                match component {
                    Component::Normal(_) => depth += 1,
                    Component::CurDir => (),
                    Component::ParentDir if depth > 0 => depth -= 1,
                    _ => return Err("Symlink escapes application bundle".into()),
                }
            }
        } else if !entry.header().entry_type().is_file() && !entry.header().entry_type().is_dir() {
            return Err("Unsupported archive entry type".into());
        }
        // Kept identical to tauri-plugin-updater 2.11.0's macOS extraction.
        let extraction_path = destination.join(relative);
        if let Some(parent) = extraction_path.parent() { fs::create_dir_all(parent)?; }
        entry.unpack(&extraction_path)?;
        count += 1;
    }
    if count == 0 || !destination.join("Contents/Info.plist").is_file() ||
        !destination.join("Contents/MacOS/burniso-usb").is_file() {
        return Err("Incomplete app bundle".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 { return Err("Usage: verify_update_archive ARCHIVE EMPTY-DEST.app".into()); }
    let destination = Path::new(&args[1]);
    // Never overwrite an installation; caller provides a fresh temporary path.
    fs::create_dir(destination)?;
    unpack(Path::new(&args[0]), destination)?;
    println!("Updater extraction verified: {}", destination.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use flate2::{write::GzEncoder, Compression};
    fn fixture(path: &Path, names: &[&str]) {
        let mut tar = tar::Builder::new(GzEncoder::new(fs::File::create(path).unwrap(), Compression::fast()));
        for name in names {
            let mut h = tar::Header::new_gnu(); h.set_size(1); h.set_mode(0o755); h.set_cksum();
            tar.append_data(&mut h, name, io::Cursor::new(b"x")).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
    }
    #[test]
    fn actual_unpack_and_appledouble_regression() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("update.tar.gz");
        fixture(&archive, &["Test.app/Contents/Info.plist", "Test.app/Contents/MacOS/burniso-usb"]);
        assert!(unpack(&archive, &tmp.path().join("good.app")).is_ok());
        fixture(&archive, &["._Test.app"]);
        assert!(unpack(&archive, &tmp.path().join("bad.app")).is_err());
        fixture(&archive, &["Test.app/Contents/._Info.plist"]);
        assert!(unpack(&archive, &tmp.path().join("bad2.app")).is_err());
        fixture(&archive, &["Test.app/Contents/Info.plist"]);
        assert!(unpack(&archive, &tmp.path().join("incomplete.app")).is_err());
    }
}
