use std::{
    collections::HashSet,
    fs,
    io::{self},
    path::Path,
};

use apk_info_axml::axml::AXML;
use apk_info_zip::{
    entry::ZipEntry,
    errors::{FileCompressionType, ZipError},
};
use serde::Deserialize;

use crate::{errors::APKError, models::ApkJson};

#[derive(Deserialize)]
struct XAPKManifest {
    package_name: String,
}

pub struct Apk {
    zip: ZipEntry,
    axml: AXML,
}

/// Implementation of internal methods
impl Apk {
    fn init_zip_and_axml(p: &Path) -> Result<(ZipEntry, AXML), APKError> {
        let input = fs::read(p).map_err(APKError::IoError)?;

        if input.is_empty() {
            return Err(APKError::InvalidInput("got empty file"));
        }

        let zip = ZipEntry::new(input).map_err(APKError::ZipError)?;

        match zip.read("AndroidManifest.xml") {
            Ok((manifest, _)) => {
                if manifest.is_empty() {
                    return Err(APKError::InvalidInput(
                        "AndroidManifest.xml is empty, not a valid apk",
                    ));
                }

                let axml = AXML::new(&mut &manifest[..]).map_err(APKError::ManifestError)?;
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
                let (inner_apk_data, _) = zip.read(&package_name).map_err(APKError::ZipError)?;

                let inner_apk = ZipEntry::new(inner_apk_data).map_err(APKError::ZipError)?;

                // try again read AndroidManifest.xml from inner apk
                let (inner_manifest, _) = inner_apk
                    .read("AndroidManifest.xml")
                    .map_err(APKError::ZipError)?;

                if inner_manifest.is_empty() {
                    return Err(APKError::InvalidInput(
                        "AndroidManifest.xml in inner apk is empty, not a valid xapk",
                    ));
                }

                let axml = AXML::new(&mut &inner_manifest[..]).map_err(APKError::ManifestError)?;

                Ok((zip, axml))
            }
        }
    }
}

impl Apk {
    pub fn new(path: &Path) -> Result<Apk, APKError> {
        // perform basic sanity check
        if !path.exists() {
            return Err(APKError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found",
            )));
        }

        let (zip, axml) = Self::init_zip_and_axml(path)?;

        Ok(Apk { zip, axml })
    }

    pub fn get_all_information(&self, pretty: bool) -> String {
        let info = ApkJson {
            package_name: self.get_package_name().map(String::from),
            min_sdk_version: self.get_min_sdk_version().map(String::from),
            target_sdk_version: self.get_target_sdk_version().map(String::from),
            max_sdk_version: self.get_max_sdk_version().map(String::from),
            declared_permissions: self
                .get_declared_permissions()
                .into_iter()
                .map(String::from)
                .collect(),
            shared_user_id: self.get_shared_user_id().map(String::from),
            shared_user_label: self.get_shared_user_label().map(String::from),
            shared_user_max_sdk_version: self.get_shared_user_max_sdk_version().map(String::from),
            version_code: self.get_version_code().map(String::from),
            version_name: self.get_version_name().map(String::from),
            install_location: self.get_install_location().map(String::from),
            features: self.get_features().into_iter().map(String::from).collect(),
            permissions: self
                .get_permissions()
                .into_iter()
                .map(String::from)
                .collect(),
            permissions_sdk23: self
                .get_permissions_sdk23()
                .into_iter()
                .map(String::from)
                .collect(),
        };

        // TODO: remove unwrap
        if pretty {
            serde_json::to_string_pretty(&info).unwrap()
        } else {
            serde_json::to_string(&info).unwrap()
        }
    }

    /// Read data from zip by filename
    pub fn read(&self, filename: &str) -> Result<(Vec<u8>, FileCompressionType), ZipError> {
        self.zip.read(filename)
    }

    /// List of the filenames included in the central directory
    pub fn get_files(&self) -> Vec<&String> {
        self.zip.namelist().collect()
    }

    // extract information from manifest tag

    /// Retrieves the package name defined in the `<manifest>` tag.
    pub fn get_package_name(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "package")
    }

    pub fn get_shared_user_id(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "sharedUserId")
    }

    pub fn get_shared_user_label(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "sharedUserLabel")
    }

    pub fn get_shared_user_max_sdk_version(&self) -> Option<&str> {
        self.axml
            .get_attribute_value("manifest", "sharedUserMaxSdkVersion")
    }

    pub fn get_version_code(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "versionCode")
    }

    pub fn get_version_name(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "versionName")
    }

    pub fn get_install_location(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "installLocation")
    }

    // extract information from other tags

    pub fn get_features(&self) -> HashSet<&str> {
        self.axml
            .get_all_attribute_values("uses-feature", "name")
            .collect()
    }

    pub fn get_permissions(&self) -> HashSet<&str> {
        // TODO: some apk uses "<android:uses-permission", wtf this is
        self.axml
            .get_all_attribute_values("uses-permission", "name")
            .collect()
    }

    pub fn get_permissions_sdk23(&self) -> HashSet<&str> {
        self.axml
            .get_all_attribute_values("uses-permission-sdk-23", "name")
            .collect()
    }

    // extract information from sdk

    /// Retrieves the minimum SDK version required by the app.
    ///
    /// See: https://developer.android.com/guide/topics/manifest/uses-sdk-element#min
    pub fn get_min_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "minSdkVersion")
    }

    /// Retrieves the target SDK version requested by the app.
    ///
    /// See: https://developer.android.com/guide/topics/manifest/uses-sdk-element#target
    pub fn get_target_sdk_version(&self) -> Option<&str> {
        self.axml
            .get_attribute_value("uses-sdk", "targetSdkVersion")
    }

    /// Retrieves the maximum SDK version supported by the app.
    ///
    /// See: https://developer.android.com/guide/topics/manifest/uses-sdk-element#max
    pub fn get_max_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "maxSdkVersion")
    }

    // extract information from permission tag

    pub fn get_declared_permissions(&self) -> HashSet<&str> {
        // TODO: maybe create some kind of structure, idk
        self.axml
            .get_all_attribute_values("permission", "name")
            .collect()
    }
}
