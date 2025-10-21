use std::collections::HashSet;
use std::path::PathBuf;

use ::apk_info::apk::Apk as ApkRust;
use pyo3::exceptions::{PyException, PyFileNotFoundError, PyTypeError, PyValueError};
use pyo3::types::PyString;
use pyo3::{Bound, PyAny, PyResult, pyclass, pymethods};
use pyo3::{create_exception, prelude::*};

create_exception!(m, APKError, PyException, "Got error while parsing apk");

#[pyclass(name = "APK")]
struct Apk {
    /// Store rust object in memory
    apkrs: ApkRust,
}

#[pymethods]
impl Apk {
    #[new]
    pub fn new(path: &Bound<'_, PyAny>) -> PyResult<Apk> {
        let resolved: Option<PathBuf> = if let Ok(s) = path.extract::<&str>() {
            Some(PathBuf::from(s))
        } else {
            path.extract::<PathBuf>().ok()
        };

        let path = resolved.ok_or_else(|| PyTypeError::new_err("expected str | Path"))?;
        if !path.exists() {
            return Err(PyFileNotFoundError::new_err(format!(
                "file not found: {:?}",
                path
            )));
        }

        let apkrs = ApkRust::new(&path).map_err(|e| APKError::new_err(e.to_string()))?;

        Ok(Apk { apkrs })
    }

    /// Read data from zip by filename
    pub fn read(&self, filename: &Bound<'_, PyString>) -> PyResult<Vec<u8>> {
        let filename = match filename.extract::<&str>() {
            Ok(name) => name,
            Err(_) => return Err(PyValueError::new_err("bad filename")),
        };

        match self.apkrs.read(filename) {
            Ok((data, _)) => {
                // TODO: return compression type
                Ok(data)
            }
            Err(e) => Err(APKError::new_err(e.to_string())),
        }
    }

    /// List of the filenames included in the central directory
    pub fn get_files(&self) -> Vec<&String> {
        self.apkrs.get_files().collect()
    }

    /// Retrieves the package name defined in the `<manifest>` tag.
    pub fn get_package_name(&self) -> Option<&str> {
        self.apkrs.get_package_name()
    }

    /// Retrieves the minimum SDK version required by the app.
    pub fn get_min_sdk_version(&self) -> Option<&str> {
        self.apkrs.get_min_sdk_version()
    }

    /// Retrieves the maximum SDK version supported by the app.
    pub fn get_max_sdk_version(&self) -> Option<&str> {
        self.apkrs.get_max_sdk_version()
    }

    pub fn get_main_activities(&self) -> HashSet<&str> {
        self.apkrs.get_main_activities().collect()
    }

    pub fn get_permissions(&self) -> HashSet<&str> {
        self.apkrs.get_permissions().collect()
    }
}

#[pymodule]
fn apk_info(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("APKError", m.py().get_type::<APKError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_class::<Apk>()?;
    Ok(())
}
