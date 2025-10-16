use std::{
    fs,
    path::{Path, PathBuf},
};

use axml::axml::AXML;
use pyo3::{
    exceptions::{PyFileNotFoundError, PyIOError, PyTypeError, PyValueError},
    prelude::*,
    types::PyString,
};
use serde::Deserialize;
use zip::entry::ZipEntry;

#[derive(Deserialize)]
struct XAPKManifest {
    package_name: String,
}

#[pyclass]
pub struct APK {
    #[pyo3(get)]
    path: PathBuf,
    zip: ZipEntry,
    axml: AXML,
}

/// Implementation of internal methods
impl APK {
    fn init_zip_and_axml(p: &Path) -> PyResult<(ZipEntry, AXML)> {
        let input = fs::read(p).map_err(|_| PyIOError::new_err("can't open given file"))?;

        let zip = ZipEntry::new(input).map_err(|e| {
            PyValueError::new_err(format!("got error while parsing zip entry: {:?}", e))
        })?;

        match zip.read("AndroidManifest.xml") {
            Ok((manifest, _)) => {
                let axml = AXML::new(&mut &manifest[..]).map_err(|e| {
                    PyValueError::new_err(format!("got error while parsing axml: {:?}", e))
                })?;
                Ok((zip, axml))
            }
            Err(_) => {
                // maybe this is xapk?
                let (manifest_json_data, _) = zip.read("manifest.json").map_err(|_| {
                    PyValueError::new_err(
                        "can't find AndroidManifest.xml or manifest.json, is it apk/xapk?",
                    )
                })?;

                let manifest_json: XAPKManifest = serde_json::from_slice(&manifest_json_data)
                    .map_err(|_| PyValueError::new_err("can't parse manifest.json"))?;

                let package_name = format!("{}.apk", manifest_json.package_name);
                let (inner_apk_data, _) = zip.read(&package_name).map_err(|_| {
                    PyValueError::new_err(format!("can't find inner apk '{}'", package_name))
                })?;

                let inner_apk = ZipEntry::new(inner_apk_data)
                    .map_err(|_| PyValueError::new_err("inner apk is not a valid zip"))?;

                // try again read AndroidManifest.xml from inner apk
                let (inner_manifest, _) = inner_apk.read("AndroidManifest.xml").map_err(|_| {
                    PyValueError::new_err(
                        "can't find AndroidManifest.xml in inner apk, not a valid apk/xapk",
                    )
                })?;

                let axml = AXML::new(&mut &inner_manifest[..]).map_err(|e| {
                    PyValueError::new_err(format!(
                        "got error while parsing axml in inner apk: {:?}",
                        e
                    ))
                })?;

                // Возвращаем оригинальный zip и axml (по ТЗ)
                Ok((zip, axml))
            }
        }
    }
}

#[pymethods]
impl APK {
    #[new]
    pub fn new(path: &Bound<'_, PyAny>) -> PyResult<APK> {
        let resolved: Option<PathBuf> = if let Ok(s) = path.extract::<&str>() {
            Some(PathBuf::from(s))
        } else if let Ok(p) = path.extract::<PathBuf>() {
            Some(p)
        } else {
            None
        };

        let p = resolved.ok_or_else(|| PyTypeError::new_err("expected str | Path"))?;
        if !p.exists() {
            return Err(PyFileNotFoundError::new_err(format!(
                "file not found: {}",
                p.display()
            )));
        }

        let (zip, axml) = Self::init_zip_and_axml(&p)?;

        Ok(APK { path: p, zip, axml })
    }

    /// Read data from zip by filename
    pub fn read(&self, filename: &Bound<'_, PyString>) -> PyResult<Vec<u8>> {
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
    pub fn get_files(&self) -> Vec<&String> {
        self.zip.namelist().collect()
    }

    /// Retrieves the package name defined in the `<manifest>` tag.
    pub fn get_package_name(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "package")
    }

    /// Retrieves the minimum SDK version required by the app.
    pub fn get_min_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "minSdkVersion")
    }

    /// Retrieves the maximum SDK version supported by the app.
    pub fn get_max_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "maxSdkVersion")
    }
}

#[pymodule]
fn _apk(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<APK>()?;
    Ok(())
}
