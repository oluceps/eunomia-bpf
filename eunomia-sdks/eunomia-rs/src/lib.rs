use std::ffi::OsString;
use std::iter::repeat_with;
use std::path::{Path, PathBuf};
use std::{env, fs, io, mem};

pub struct TempDir {
    path: Box<Path>,
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn create_tmp_dir(path: PathBuf) -> io::Result<TempDir> {
    match fs::create_dir(&path) {
        // tmp workspace exist, return as well
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(TempDir {
            path: path.into_boxed_path(),
        }),
        Ok(i) => Ok(i).map(|_| TempDir {
            path: path.into_boxed_path(),
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Cannot create temporary workspace",
        )),
    }
}

impl TempDir {
    /// Create a temporary directory with random suffix
    pub fn new() -> io::Result<TempDir> {
        let tmp_dir_from_env = &env::temp_dir();

        let mut buf = OsString::with_capacity(8 + 6);
        let mut char_buf = [0u8; 4];
        buf.push("eunomia.");

        for c in repeat_with(fastrand::alphanumeric).take(6) {
            buf.push(c.encode_utf8(&mut char_buf));
        }

        let path = tmp_dir_from_env.join(buf);

        create_tmp_dir(path)
    }

    /// Return path of temporary directory
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub fn close(mut self) -> io::Result<()> {
        let result = fs::remove_dir_all(self.path());

        self.path = PathBuf::new().into_boxed_path();

        mem::forget(self);

        result
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.path());
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
