use std::fs;
use std::io::{self};
use std::path::Path;

use apk_info_axml::axml::AXML;
use apk_info_zip::entry::ZipEntry;
use apk_info_zip::errors::{FileCompressionType, ZipError};
use apk_info_zip::signature::Signature;

use crate::errors::APKError;
use crate::models::{ApkJson, Application, XAPKManifest};

/// Main structure that represents APK file
pub struct Apk {
    zip: ZipEntry,
    axml: AXML,
}

/// Implementation of internal methods
impl Apk {
    /// Helper function for reading apk files
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

                let manifest_json: XAPKManifest = serde_json::from_slice(&manifest_json_data)
                    .map_err(APKError::XAPKManifestError)?;

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
            declared_permissions: self.get_declared_permissions().map(String::from).collect(),
            shared_user_id: self.get_shared_user_id().map(String::from),
            shared_user_label: self.get_shared_user_label().map(String::from),
            shared_user_max_sdk_version: self.get_shared_user_max_sdk_version().map(String::from),
            version_code: self.get_version_code().map(String::from),
            version_name: self.get_version_name().map(String::from),
            install_location: self.get_install_location().map(String::from),
            features: self.get_features().map(String::from).collect(),
            permissions: self.get_permissions().map(String::from).collect(),
            permissions_sdk23: self.get_permissions_sdk23().map(String::from).collect(),
            application: Application {
                allow_task_reparenting: self.get_application_task_reparenting().map(String::from),
                allow_backup: self.get_application_allow_backup().map(String::from),
                app_category: self.get_application_category().map(String::from),
                backup_agent: self.get_application_backup_agent().map(String::from),
                debuggable: self.get_application_debuggable().map(String::from),
                description: self.get_application_description().map(String::from),
                label: self.get_application_label().map(String::from),
                name: self.get_application_name().map(String::from),
            },
            main_activities: self.get_main_activities().map(String::from).collect(),
            libraries: self.get_libraries().map(String::from).collect(),
            activities: self.get_activities().map(String::from).collect(),
            services: self.get_services().map(String::from).collect(),
            receivers: self.get_receivers().map(String::from).collect(),
            providers: self.get_providers().map(String::from).collect(),
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
    pub fn get_files(&self) -> impl Iterator<Item = &String> {
        self.zip.namelist()
    }

    /// Retrieves the package name defined in the `<manifest>` tag
    ///
    /// Example:
    /// ```xml
    /// <manifest package="com.example.app" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#package>
    pub fn get_package_name(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "package")
    }

    /// Retrieves the `sharedUserId` defined in the `<manifest>` tag.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uid>
    pub fn get_shared_user_id(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "sharedUserId")
    }

    /// Retrieves the `sharedUserLabel` defined in the `<manifest>` tag.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uidlabel>
    pub fn get_shared_user_label(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "sharedUserLabel")
    }

    /// Retrieves the `sharedUserMaxSdkVersion` defined in the `<manifest>` tag.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uidmaxsdk>
    pub fn get_shared_user_max_sdk_version(&self) -> Option<&str> {
        self.axml
            .get_attribute_value("manifest", "sharedUserMaxSdkVersion")
    }

    /// Retrieves the application version code.
    ///
    /// Example:
    /// ```xml
    /// <manifest android:versionCode="42" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#vcode>
    pub fn get_version_code(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "versionCode")
    }

    /// Retrieves the application version name.
    ///
    /// Example:
    /// ```xml
    /// <manifest android:versionName="1.2.3" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#vname>
    pub fn get_version_name(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "versionName")
    }

    /// Retrieves the preferred installation location.
    ///
    /// Possible values: `"auto"`, `"internalOnly"`, `"preferExternal"`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#install>
    pub fn get_install_location(&self) -> Option<&str> {
        self.axml.get_attribute_value("manifest", "installLocation")
    }

    /// Extract information from `<application android:allowTaskReparenting="true | false">`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#reparent>
    pub fn get_application_task_reparenting(&self) -> Option<&str> {
        self.axml
            .get_attribute_value("application", "allowTaskReparenting")
    }

    /// Extract information from `<application android:allowBackup="true | false"`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#allowbackup>
    pub fn get_application_allow_backup(&self) -> Option<&str> {
        self.axml.get_attribute_value("application", "allowBackup")
    }

    /// Extracts the `android:appCategory` attribute from `<application>`.
    ///
    /// Possible values include: `"accessibility"`, `"audio"`, `"game"`, `"image"`,
    /// `"maps"`, `"news"`, `"productivity"`, `"social"`, `"video"`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#appCategory>
    pub fn get_application_category(&self) -> Option<&str> {
        self.axml.get_attribute_value("application", "appCategory")
    }

    /// Extracts the `android:backupAgent` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#agent>
    pub fn get_application_backup_agent(&self) -> Option<&str> {
        self.axml.get_attribute_value("application", "backupAgent")
    }

    /// Extracts the `android:debuggable` attribute from `<application>`.
    ///
    /// Example:
    /// ```xml
    /// <application android:debuggable="true" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#debug>
    pub fn get_application_debuggable(&self) -> Option<&str> {
        self.axml.get_attribute_value("application", "debuggable")
    }

    /// Extracts the `android:description` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#desc>
    pub fn get_application_description(&self) -> Option<&str> {
        // TODO: resolve with resources
        self.axml.get_attribute_value("application", "description")
    }

    /// Extracts the `android:label` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#label>
    pub fn get_application_label(&self) -> Option<&str> {
        // TODO: probably not so easy
        self.axml.get_attribute_value("application", "label")
    }

    /// Extracts the `android:name` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#nm>
    pub fn get_application_name(&self) -> Option<&str> {
        // TODO: probably not so easy
        self.axml.get_attribute_value("application", "name")
    }

    /// Retrieves all declared permissions from `<uses-permission android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-permission-element>
    pub fn get_permissions(&self) -> impl Iterator<Item = &str> {
        // TODO: some apk uses "<android:uses-permission", wtf this is
        self.axml
            .get_all_attribute_values("uses-permission", "name")
    }

    /// Retrieves all declared permissions for API 23+ from `<uses-permission-sdk-23>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-permission-sdk-23-element>
    pub fn get_permissions_sdk23(&self) -> impl Iterator<Item = &str> {
        self.axml
            .get_all_attribute_values("uses-permission-sdk-23", "name")
    }

    /// Retrieves the minimum SDK version required by the app.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#min>
    pub fn get_min_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "minSdkVersion")
    }

    /// Retrieves the target SDK version requested by the app.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#target>
    pub fn get_target_sdk_version(&self) -> Option<&str> {
        self.axml
            .get_attribute_value("uses-sdk", "targetSdkVersion")
    }

    /// Retrieves the maximum SDK version supported by the app.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#max>
    pub fn get_max_sdk_version(&self) -> Option<&str> {
        self.axml.get_attribute_value("uses-sdk", "maxSdkVersion")
    }

    /// Retrieves all libraries declared by `<uses-library android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-library-element>
    pub fn get_libraries(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("uses-library", "name")
    }

    /// Retrieves all hardware or software features declared by `<uses-feature>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element>
    pub fn get_features(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("uses-feature", "name")
    }

    /// Retrieves all declared permissions defined by `<permission android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element>
    pub fn get_declared_permissions(&self) -> impl Iterator<Item = &str> {
        // TODO: maybe create some kind of structure, idk
        self.axml.get_all_attribute_values("permission", "name")
    }

    /// Retrieves all **main activities** (with intent filters `MAIN` + `LAUNCHER|INFO`).
    pub fn get_main_activities(&self) -> impl Iterator<Item = &str> {
        self.axml.get_main_activities()
    }

    /// Retrieves all activities declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element>
    pub fn get_activities(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("activity", "name")
    }

    /// Retrieves all services declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element>
    pub fn get_services(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("service", "name")
    }

    /// Retrieves all receivers declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element>
    pub fn get_receivers(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("receiver", "name")
    }

    /// Retrieves all providers declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element>
    pub fn get_providers(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("provider", "name")
    }

    /// Retrieves all APK signing signatures (v1, v2, v3 and v3.1).
    ///
    /// Combines results from multiple signature blocks within the APK file.
    pub fn get_signatures(&self) -> Result<Vec<Signature>, APKError> {
        // TODO: need somehow also detect xapk files
        let mut signatures = self.zip.get_signatures_other()?;

        if let Ok(v1_sig) = self.zip.get_signature_v1() {
            signatures.push(v1_sig);
        }

        Ok(signatures)
    }
}
