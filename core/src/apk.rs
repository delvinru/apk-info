use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use apk_info_axml::ARSC;
use apk_info_axml::axml::AXML;
use apk_info_zip::{FileCompressionType, Signature, ZipEntry, ZipError};

use crate::errors::APKError;
use crate::models::{Receiver, Service, XAPKManifest};

const ANDROID_MANIFEST_PATH: &str = "AndroidManifest.xml";
const RESOURCE_TABLE_PATH: &str = "resources.arsc";

// maybe in the future
#[allow(unused)]
const PROTO_RESOURCE_TABLE_PATH: &str = "resources.pb";

/// Main structure that represents APK file
pub struct Apk {
    zip: ZipEntry,
    axml: AXML,
    arsc: Option<ARSC>,
}

/// Implementation of internal methods
impl Apk {
    /// Helper function for reading apk files
    fn init(p: &Path) -> Result<(ZipEntry, AXML, Option<ARSC>), APKError> {
        let file = File::open(p).map_err(APKError::IoError)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        let mut input = Vec::new();
        reader.read_to_end(&mut input).map_err(APKError::IoError)?;

        if input.is_empty() {
            return Err(APKError::InvalidInput("got empty file"));
        }

        let zip = ZipEntry::new(input).map_err(APKError::ZipError)?;

        match zip.read(ANDROID_MANIFEST_PATH) {
            Ok((manifest, _)) => {
                if manifest.is_empty() {
                    return Err(APKError::InvalidInput(
                        "AndroidManifest.xml is empty, not a valid apk",
                    ));
                }

                // d5b7d025712f0f22562b3d511d7603f5c8a0c477675c6578083fa7709ca41ba8 - sample without resourcers, but in theory we can show information, need research
                let arsc = match zip.read(RESOURCE_TABLE_PATH) {
                    Ok((resource_data, _)) => {
                        Some(ARSC::new(&mut &resource_data[..]).map_err(APKError::ResourceError)?)
                    }
                    Err(_) => None,
                };

                let axml = AXML::new(&mut &manifest[..], arsc.as_ref())
                    .map_err(APKError::ManifestError)?;

                Ok((zip, axml, arsc))
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
                    .read(ANDROID_MANIFEST_PATH)
                    .map_err(APKError::ZipError)?;

                if inner_manifest.is_empty() {
                    return Err(APKError::InvalidInput(
                        "AndroidManifest.xml in inner apk is empty, not a valid xapk",
                    ));
                }

                // d5b7d025712f0f22562b3d511d7603f5c8a0c477675c6578083fa7709ca41ba8 - sample without resourcers, but in theory we can show information, need research
                // 3474625e63d0893fc8f83034e835472d95195254e1e4bdf99153b7c74eb44d86 - same
                let arsc = match zip.read(RESOURCE_TABLE_PATH) {
                    Ok((resource_data, _)) => {
                        Some(ARSC::new(&mut &resource_data[..]).map_err(APKError::ResourceError)?)
                    }
                    Err(_) => None,
                };

                let axml = AXML::new(&mut &inner_manifest[..], arsc.as_ref())
                    .map_err(APKError::ManifestError)?;

                Ok((zip, axml, arsc))
            }
        }
    }
}

impl Apk {
    pub fn new(path: &Path) -> Result<Apk, APKError> {
        // basic sanity check
        if !path.exists() {
            return Err(APKError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                "file not found",
            )));
        }

        let (zip, axml, arsc) = Self::init(path)?;

        Ok(Apk { zip, axml, arsc })
    }

    /// Read data from zip by filename
    #[inline]
    pub fn read(&self, filename: &str) -> Result<(Vec<u8>, FileCompressionType), ZipError> {
        self.zip.read(filename)
    }

    /// List of the filenames included in the central directory
    #[inline]
    pub fn namelist(&self) -> impl Iterator<Item = &str> + '_ {
        self.zip.namelist()
    }

    /// Returns nice representation of `AndroidManifest.xml`
    pub fn get_xml_string(&self) -> String {
        self.axml.get_xml_string()
    }

    /// Check if the APK has multiple dex files or not
    pub fn is_multidex(&self) -> bool {
        self.zip
            .namelist()
            .filter(|name| {
                // don't use regexes, i think it's overengineering for this task
                if !name.starts_with("classes") || !name.ends_with(".dex") {
                    return false;
                }

                let middle = &name["classes".len()..name.len() - ".dex".len()];

                middle.is_empty() || middle.chars().all(|c| c.is_ascii_digit())
            })
            .count()
            > 1
    }

    #[inline]
    pub fn get_attribute_value(&self, tag: &str, name: &str) -> Option<String> {
        self.axml.get_attribute_value(tag, name, self.arsc.as_ref())
    }

    #[inline]
    pub fn get_all_attribute_values<'a>(
        &'a self,
        tag: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> {
        self.axml.get_all_attribute_values(tag, name)
    }

    /// Retrieves the package name defined in the `<manifest>` tag
    ///
    /// Example:
    /// ```xml
    /// <manifest package="com.example.app" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#package>
    #[inline]
    pub fn get_package_name(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "package", self.arsc.as_ref())
    }

    /// Retrieves the `sharedUserId` defined in the `<manifest>` tag.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uid>
    #[inline]
    pub fn get_shared_user_id(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "sharedUserId", self.arsc.as_ref())
    }

    /// Retrieves the `sharedUserLabel` defined in the `<manifest>` tag.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uidlabel>
    #[inline]
    pub fn get_shared_user_label(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "sharedUserLabel", self.arsc.as_ref())
    }

    /// Retrieves the `sharedUserMaxSdkVersion` defined in the `<manifest>` tag.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uidmaxsdk>
    #[inline]
    pub fn get_shared_user_max_sdk_version(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "sharedUserMaxSdkVersion", self.arsc.as_ref())
    }

    /// Retrieves the application version code.
    ///
    /// Example:
    /// ```xml
    /// <manifest android:versionCode="42" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#vcode>
    #[inline]
    pub fn get_version_code(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "versionCode", self.arsc.as_ref())
    }

    /// Retrieves the application version name.
    ///
    /// Example:
    /// ```xml
    /// <manifest android:versionName="1.2.3" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#vname>
    #[inline]
    pub fn get_version_name(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "versionName", self.arsc.as_ref())
    }

    /// Retrieves the preferred installation location.
    ///
    /// Possible values: `"auto"`, `"internalOnly"`, `"preferExternal"`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#install>
    #[inline]
    pub fn get_install_location(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "installLocation", self.arsc.as_ref())
    }

    /// Extract information from `<application android:allowTaskReparenting="true | false">`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#reparent>
    #[inline]
    pub fn get_application_task_reparenting(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "allowTaskReparenting", self.arsc.as_ref())
    }

    /// Extract information from `<application android:allowBackup="true | false"`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#allowbackup>
    #[inline]
    pub fn get_application_allow_backup(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "allowBackup", self.arsc.as_ref())
    }

    /// Extracts the `android:appCategory` attribute from `<application>`.
    ///
    /// Possible values include: `"accessibility"`, `"audio"`, `"game"`, `"image"`,
    /// `"maps"`, `"news"`, `"productivity"`, `"social"`, `"video"`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#appCategory>
    #[inline]
    pub fn get_application_category(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "appCategory", self.arsc.as_ref())
    }

    /// Extracts the `android:backupAgent` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#agent>
    #[inline]
    pub fn get_application_backup_agent(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "backupAgent", self.arsc.as_ref())
    }

    /// Extracts the `android:debuggable` attribute from `<application>`.
    ///
    /// Example:
    /// ```xml
    /// <application android:debuggable="true" />
    /// ```
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#debug>
    #[inline]
    pub fn get_application_debuggable(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "debuggable", self.arsc.as_ref())
    }

    /// Extracts the `android:description` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#desc>
    #[inline]
    pub fn get_application_description(&self) -> Option<String> {
        // TODO: resolve with resources
        self.axml
            .get_attribute_value("application", "description", self.arsc.as_ref())
    }

    /// Extracts the `android:icon` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#icon>
    #[inline]
    pub fn get_application_icon(&self) -> Option<String> {
        // TODO: need somehow resolve maximum resolution for icon or give option to search density
        self.axml
            .get_attribute_value("application", "icon", self.arsc.as_ref())
    }

    /// Extracts the `android:label` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#label>
    #[inline]
    pub fn get_application_label(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "label", self.arsc.as_ref())
    }

    /// Extracts the `android:name` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#nm>
    #[inline]
    pub fn get_application_name(&self) -> Option<String> {
        // TODO: probably not so easy
        self.axml
            .get_attribute_value("application", "name", self.arsc.as_ref())
    }

    /// Retrieves all declared permissions from `<uses-permission android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-permission-element>
    #[inline]
    pub fn get_permissions(&self) -> impl Iterator<Item = &str> {
        self.axml
            .get_all_attribute_values("uses-permission", "name")
    }

    /// Retrieves all declared permissions for API 23+ from `<uses-permission-sdk-23>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-permission-sdk-23-element>
    #[inline]
    pub fn get_permissions_sdk23(&self) -> impl Iterator<Item = &str> {
        self.axml
            .get_all_attribute_values("uses-permission-sdk-23", "name")
    }

    /// Retrieves the minimum SDK version required by the app.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#min>
    #[inline]
    pub fn get_min_sdk_version(&self) -> Option<String> {
        self.axml
            .get_attribute_value("uses-sdk", "minSdkVersion", self.arsc.as_ref())
    }

    /// Retrieves the target SDK version requested by the app.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#target>
    #[inline]
    pub fn get_target_sdk_version(&self) -> Option<String> {
        self.axml
            .get_attribute_value("uses-sdk", "targetSdkVersion", self.arsc.as_ref())
    }

    /// Retrieves the maximum SDK version supported by the app.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#max>
    #[inline]
    pub fn get_max_sdk_version(&self) -> Option<String> {
        self.axml
            .get_attribute_value("uses-sdk", "maxSdkVersion", self.arsc.as_ref())
    }

    /// Retrieves all libraries declared by `<uses-library android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-library-element>
    #[inline]
    pub fn get_libraries(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("uses-library", "name")
    }

    /// Retrieves all hardware or software features declared by `<uses-feature>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element>
    #[inline]
    pub fn get_features(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("uses-feature", "name")
    }

    /// The app is designed to show its UI on a set of screens inside a vehicle
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    pub fn is_automotive(&self) -> bool {
        self.get_features()
            .any(|x| x == "android.hardware.type.automotive")
    }

    /// The app is designed to show its UI on a television
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    pub fn is_leanback(&self) -> bool {
        self.get_features()
            .any(|x| x == "android.hardware.type.television" || x == "android.software.leanback")
    }

    /// The app is designed to show its UI on a watch.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    pub fn is_wearable(&self) -> bool {
        self.get_features()
            .any(|x| x == "android.hardware.type.watch")
    }

    /// The app is designed to show its UI on Chromebooks.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    pub fn is_chromebook(&self) -> bool {
        self.get_features().any(|x| x == "android.hardware.type.pc")
    }

    /// Retrieves all declared permissions defined by `<permission android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element>
    #[inline]
    pub fn get_declared_permissions(&self) -> impl Iterator<Item = &str> {
        // TODO: maybe create some kind of structure, idk
        self.axml.get_all_attribute_values("permission", "name")
    }

    /// Get first found main activity (with intent filters `MAIN` + `LAUNCHER|INFO`)
    #[inline]
    pub fn get_main_activity(&self) -> Option<&str> {
        self.axml.get_main_activities().next()
    }

    /// Retrieves all **main activities** (with intent filters `MAIN` + `LAUNCHER|INFO`).
    #[inline]
    pub fn get_main_activities(&self) -> impl Iterator<Item = &str> {
        self.axml.get_main_activities()
    }

    /// Retrieves all activities declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element>
    #[inline]
    pub fn get_activities(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("activity", "name")
    }

    /// Retrieves all services declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element>
    pub fn get_services<'a>(&'a self) -> impl Iterator<Item = Service<'a>> {
        self.axml
            .root
            .descendants()
            .filter(|&el| el.name() == "service")
            .map(|el| Service {
                description: el.attr("description"),
                direct_boot_aware: el.attr("direct_boot_aware"),
                enabled: el.attr("enabled"),
                exported: el.attr("exported"),
                foreground_service_type: el.attr("foreground_service_type"),
                isolated_process: el.attr("isolated_process"),
                name: el.attr("name"),
                permission: el.attr("permission"),
                process: el.attr("process"),
                stop_with_task: el.attr("stop_with_task"),
            })
    }

    /// Retrieves all receivers declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element>
    pub fn get_receivers<'a>(&'a self) -> impl Iterator<Item = Receiver<'a>> {
        self.axml
            .root
            .descendants()
            .filter(|&el| el.name() == "receiver")
            .map(|el| Receiver {
                direct_boot_aware: el.attr("direct_boot_aware"),
                enabled: el.attr("enabled"),
                exported: el.attr("exported"),
                icon: el.attr("icon"),
                label: el.attr("label"),
                name: el.attr("name"),
                permission: el.attr("permission"),
                process: el.attr("process"),
            })
    }

    /// Retrieves all providers declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element>
    #[inline]
    pub fn get_providers(&self) -> impl Iterator<Item = &str> {
        self.axml.get_all_attribute_values("provider", "name")
    }

    /// Retrieves all APK signing signatures (v1, v2, v3 and v3.1).
    ///
    /// Combines results from multiple signature blocks within the APK file.
    pub fn get_signatures(&self) -> Result<Vec<Signature>, APKError> {
        let mut signatures = Vec::new();
        if let Ok(v1_sig) = self.zip.get_signature_v1() {
            signatures.push(v1_sig);
        }

        // TODO: need somehow also detect xapk files
        signatures.extend(
            self.zip
                .get_signatures_other()
                .map_err(APKError::CertificateError)?,
        );

        Ok(signatures)
    }
}
