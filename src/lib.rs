use std::{fs, path::PathBuf};

use axml::axml::AXML;
use pyo3::{
    exceptions::{PyFileNotFoundError, PyIOError, PyTypeError, PyValueError},
    prelude::*,
    types::PyString,
};
use zip::entry::ZipEntry;

#[pyclass]
pub struct APK {
    #[pyo3(get)]
    path: PathBuf,
    zip: ZipEntry,
    axml: AXML,
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

            let (manifest, _) = zip
                .read("AndroidManifest.xml")
                .map_err(|_| PyValueError::new_err("can't find AndroidManifest.xml, is it apk?"))?;

            let axml = AXML::new(&mut &manifest[..]).map_err(|e| {
                PyValueError::new_err(format!("got error while parsing axml: {:?}", e))
            })?;

            return Ok(APK { path: p, zip, axml });
        }

        Err(PyTypeError::new_err("expected str | Path"))
    }

    /// Read data from zip by filename
    fn read(&self, filename: &Bound<'_, PyString>) -> PyResult<Vec<u8>> {
        let filename = match filename.extract::<&str>() {
            Ok(name) => name,
            Err(_) => {
                return Err(PyValueError::new_err("bad filename"));
            }
        };

        match self.zip.read(filename) {
            Ok((data, _)) => {
                // TODO: if got tampered type need save and somehow export this value
                Ok(data)
            }
            Err(e) => Err(PyValueError::new_err(format!(
                "can't read file from zip {:?}",
                e,
            ))),
        }
    }

    /// List of the filenames included in the central directory
    fn get_files(&self) -> Vec<&String> {
        self.zip.namelist().collect()
    }

    /// Retrieves the package name defined in the `<manifest>` tag.
    fn get_package_name(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "package")
    }

    /// Retrieves the minimum SDK version required by the app.
    fn get_min_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "minSdkVersion")
    }

    /// Retrieves the maximum SDK version supported by the app.
    fn get_max_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "maxSdkVersion")
    }
}

#[pymodule]
fn _apk(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<APK>()?;
    Ok(())
}
