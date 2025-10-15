use std::{fs, path::PathBuf};

use pyo3::{
    exceptions::{PyFileNotFoundError, PyIOError, PyTypeError, PyValueError},
    prelude::*,
};
use zip::entry::ZipEntry;

#[pyclass]
pub struct APK {
    #[pyo3(get)]
    path: PathBuf,
    zip: ZipEntry,
}

#[pymethods]
impl APK {
    #[new]
    fn new(path: &Bound<'_, PyAny>) -> PyResult<APK> {
        let mut resolved: Option<PathBuf> = None;

        if let Ok(s) = path.extract::<&str>() {
            resolved = Some(PathBuf::from(s))
        } else if let Ok(p) = path.extract::<PathBuf>() {
            resolved = Some(p)
        }

        if let Some(p) = resolved {
            if !p.exists() {
                return Err(PyFileNotFoundError::new_err(format!(
                    "file not found: {}",
                    p.display()
                )));
            }

            let input = fs::read(&p).map_err(|_| PyIOError::new_err("can't open given file"))?;
            let zip = ZipEntry::new(input).map_err(|e| {
                PyValueError::new_err(format!("got error while parsing zip entry: {:?}", e))
            })?;

            return Ok(APK { path: p, zip });
        }

        Err(PyTypeError::new_err("expected str | Path"))
    }
}

#[pymodule]
fn _apk(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<APK>()?;
    Ok(())
}
