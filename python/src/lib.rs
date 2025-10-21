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

    pub fn get_package_name(&self) -> Option<&str> {
        self.apkrs.get_package_name()
    }

    pub fn get_shared_user_id(&self) -> Option<&str> {
        self.apkrs.get_shared_user_id()
    }

    pub fn get_shared_user_label(&self) -> Option<&str> {
        self.apkrs.get_shared_user_label()
    }

    pub fn get_shared_user_max_sdk_version(&self) -> Option<&str> {
        self.apkrs.get_shared_user_max_sdk_version()
    }

    pub fn get_version_code(&self) -> Option<&str> {
        self.apkrs.get_version_code()
    }

    pub fn get_version_name(&self) -> Option<&str> {
        self.apkrs.get_version_name()
    }

    pub fn get_install_location(&self) -> Option<&str> {
        self.apkrs.get_install_location()
    }

    pub fn get_application_task_reparenting(&self) -> Option<&str> {
        self.apkrs.get_application_task_reparenting()
    }

    pub fn get_application_allow_backup(&self) -> Option<&str> {
        self.apkrs.get_application_allow_backup()
    }

    pub fn get_application_category(&self) -> Option<&str> {
        self.apkrs.get_application_category()
    }

    pub fn get_application_backup_agent(&self) -> Option<&str> {
        self.apkrs.get_application_backup_agent()
    }

    pub fn get_application_debuggable(&self) -> Option<&str> {
        self.apkrs.get_application_debuggable()
    }

    pub fn get_application_description(&self) -> Option<&str> {
        self.apkrs.get_application_description()
    }

    pub fn get_application_label(&self) -> Option<&str> {
        self.apkrs.get_application_label()
    }

    pub fn get_application_name(&self) -> Option<&str> {
        self.apkrs.get_application_name()
    }

    pub fn get_permissions(&self) -> HashSet<&str> {
        self.apkrs.get_permissions().collect()
    }

    pub fn get_permissions_sdk23(&self) -> HashSet<&str> {
        self.apkrs.get_permissions_sdk23().collect()
    }

    pub fn get_min_sdk_version(&self) -> Option<&str> {
        self.apkrs.get_min_sdk_version()
    }

    pub fn get_target_sdk_version(&self) -> Option<&str> {
        self.apkrs.get_target_sdk_version()
    }

    pub fn get_max_sdk_version(&self) -> Option<&str> {
        self.apkrs.get_max_sdk_version()
    }

    pub fn get_libraries(&self) -> HashSet<&str> {
        self.apkrs.get_libraries().collect()
    }

    pub fn get_features(&self) -> HashSet<&str> {
        self.apkrs.get_features().collect()
    }

    pub fn get_declared_permissions(&self) -> HashSet<&str> {
        self.apkrs.get_declared_permissions().collect()
    }

    pub fn get_main_activities(&self) -> HashSet<&str> {
        self.apkrs.get_main_activities().collect()
    }

    pub fn get_activities(&self) -> HashSet<&str> {
        self.apkrs.get_activities().collect()
    }

    pub fn get_services(&self) -> HashSet<&str> {
        self.apkrs.get_services().collect()
    }

    pub fn get_receivers(&self) -> HashSet<&str> {
        self.apkrs.get_receivers().collect()
    }

    pub fn get_providers(&self) -> HashSet<&str> {
        self.apkrs.get_providers().collect()
    }

    // pub fn get_signatures(&self) -> Result<Vec<Signature>, APKError> {
    //     self.apkrs.get_signatures()
    // }
}

#[pymodule]
fn apk_info(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("APKError", m.py().get_type::<APKError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_class::<Apk>()?;
    Ok(())
}
