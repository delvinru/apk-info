use std::{
    fs,
    io::{self},
    path::{Path, PathBuf},
};

use apk_info_axml::axml::AXML;
use apk_info_zip::{
    entry::ZipEntry,
    errors::{FileCompressionType, ZipError},
};
use serde::Deserialize;

use crate::errors::APKError;

#[derive(Deserialize)]
struct XAPKManifest {
    package_name: String,
}

pub struct APK {
    zip: ZipEntry,
    axml: AXML,
}

/// Implementation of internal methods
impl APK {
    fn init_zip_and_axml(p: &Path) -> Result<(ZipEntry, AXML), APKError> {
        let input = fs::read(p).map_err(|e| APKError::IoError(e))?;

        if input.is_empty() {
            return Err(APKError::InvalidInput("got empty file"));
        }

        let zip = ZipEntry::new(input).map_err(|e| APKError::ZipError(e))?;

        match zip.read("AndroidManifest.xml") {
            Ok((manifest, _)) => {
                if manifest.is_empty() {
                    return Err(APKError::InvalidInput(
                        "AndroidManifest.xml is empty, not a valid apk",
                    ));
                }

                let axml = AXML::new(&mut &manifest[..]).map_err(|e| APKError::ManifestError(e))?;
                Ok((zip, axml))
            }
            Err(_) => {
                // maybe this is xapk?
                let (manifest_json_data, _) = zip.read("manifest.json").map_err(|_| {
                    APKError::InvalidInput(
                        "can't find AndroidManifest.xml or manifest.json, is it apk/xapk?",
                    )
                })?;

                // TODO: change error type
                let manifest_json: XAPKManifest = serde_json::from_slice(&manifest_json_data)
                    .map_err(|_| APKError::InvalidInput("can't parse manifest.json"))?;

                let package_name = format!("{}.apk", manifest_json.package_name);
                let (inner_apk_data, _) =
                    zip.read(&package_name).map_err(|e| APKError::ZipError(e))?;

                let inner_apk = ZipEntry::new(inner_apk_data).map_err(|e| APKError::ZipError(e))?;

                // try again read AndroidManifest.xml from inner apk
                let (inner_manifest, _) = inner_apk
                    .read("AndroidManifest.xml")
                    .map_err(|e| APKError::ZipError(e))?;

                if inner_manifest.is_empty() {
                    return Err(APKError::InvalidInput(
                        "AndroidManifest.xml in inner apk is empty, not a valid xapk",
                    ));
                }

                let axml =
                    AXML::new(&mut &inner_manifest[..]).map_err(|e| APKError::ManifestError(e))?;

                // Возвращаем оригинальный zip и axml (по ТЗ)
                Ok((zip, axml))
            }
        }
    }
}

impl APK {
    pub fn new(path: &PathBuf) -> Result<APK, APKError> {
        // perform basic sanity check
        if !path.exists() {
            return Err(APKError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found",
            )));
        }

        let (zip, axml) = Self::init_zip_and_axml(&path)?;

        Ok(APK { zip, axml })
    }

    /// Read data from zip by filename
    pub fn read(&self, filename: &str) -> Result<(Vec<u8>, FileCompressionType), ZipError> {
        self.zip.read(filename)
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
