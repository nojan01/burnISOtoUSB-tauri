//! Descriptor-relative directory traversal for the elevated, read-only scanner.
//! O_NOFOLLOW prevents a directory replaced by a symlink from escaping the scan.
use std::{ffi::{CStr, CString, OsStr, OsString}, fs::File, io, os::{fd::{AsRawFd, FromRawFd, IntoRawFd}, unix::ffi::{OsStrExt, OsStringExt}}, path::Path, ptr::NonNull};

pub struct Directory {
    stream: NonNull<libc::DIR>,
    pub device: u64,
}

impl Directory {
    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_at(libc::AT_FDCWD, root.as_os_str())
    }

    fn fd(&self) -> libc::c_int {
        // SAFETY: this instance exclusively owns the live directory stream.
        unsafe { libc::dirfd(self.stream.as_ptr()) }
    }

    fn open_at(parent: libc::c_int, name: &OsStr) -> io::Result<Self> {
        let name = CString::new(name.as_bytes())?;
        // SAFETY: name is NUL-terminated; parent is AT_FDCWD or a live dir fd.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        // SAFETY: openat returned a newly owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        use std::os::unix::fs::MetadataExt;
        let device = file.metadata()?.dev();
        // SAFETY: fdopendir receives a valid directory descriptor. Ownership is
        // transferred only on success; File closes it on every error path.
        let stream = NonNull::new(unsafe { libc::fdopendir(file.as_raw_fd()) })
            .ok_or_else(io::Error::last_os_error)?;
        let _ = file.into_raw_fd();
        Ok(Self { stream, device })
    }

    pub fn child(&self, name: &OsStr) -> io::Result<Self> {
        Self::open_at(self.fd(), name)
    }

    pub fn metadata(&self, name: &OsStr) -> io::Result<libc::stat> {
        let name = CString::new(name.as_bytes())?;
        let mut result = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid parent fd, C string and output buffer; symlinks are
        // inspected themselves, never followed to their destination.
        if unsafe { libc::fstatat(self.fd(), name.as_ptr(), result.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstatat initialized the struct on success.
        Ok(unsafe { result.assume_init() })
    }
}

impl Iterator for Directory {
    type Item = io::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // SAFETY: access this thread's errno, then read our exclusive DIR.
            // readdir's pointer is copied before the next call invalidates it.
            let entry = unsafe {
                #[cfg(target_vendor = "apple")]
                { *libc::__error() = 0; }
                #[cfg(not(target_vendor = "apple"))]
                { *libc::__errno_location() = 0; }
                libc::readdir(self.stream.as_ptr())
            };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) { None } else { Some(Err(error)) };
            }
            // SAFETY: non-null readdir result has a NUL-terminated d_name.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." { continue; }
            return Some(Ok(OsString::from_vec(name.to_vec())));
        }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: this instance owns the stream and its underlying descriptor.
        unsafe { libc::closedir(self.stream.as_ptr()); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn directory_replaced_by_symlink_is_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("child")).unwrap();
        let dir = Directory::open(root.path()).unwrap();
        assert_eq!(dir.metadata(OsStr::new("child")).unwrap().st_mode & libc::S_IFMT, libc::S_IFDIR);
        fs::remove_dir(root.path().join("child")).unwrap();
        symlink(outside.path(), root.path().join("child")).unwrap();
        assert!(dir.child(OsStr::new("child")).is_err());
        assert!(Directory::open(&root.path().join("child")).is_err());
    }

    #[test]
    fn renamed_parent_does_not_redirect_metadata_reads() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("evidence"), b"123").unwrap();
        let dir = Directory::open(&original).unwrap();
        fs::rename(&original, root.path().join("moved")).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("evidence"), b"different").unwrap();
        assert_eq!(dir.metadata(OsStr::new("evidence")).unwrap().st_size, 3);
    }
}
