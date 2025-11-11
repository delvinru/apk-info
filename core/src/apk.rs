//! The main structure that represents the `apk` file.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use apk_info_axml::{ARSC, AXML};
use apk_info_zip::{FileCompressionType, Signature, ZipEntry, ZipError};

use crate::errors::APKError;
use crate::models::{Activity, Permission, Provider, Receiver, Service, XAPKManifest};

/// The name of the manifest to be searched for in the zip archive.
const ANDROID_MANIFEST_PATH: &str = "AndroidManifest.xml";

/// The name of the resource to be searched in the zip archive.
const RESOURCE_TABLE_PATH: &str = "resources.arsc";

/// The main structure that represents the `apk` file.
#[derive(Debug)]
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
    /// Creates a new [Apk] object.
    ///
    /// Upon initialization, the apk file will be read and analyzed.
    ///
    /// ```ignore
    /// let apk = Apk::new("./file.apk").expect("can't analyze apk file");
    /// ```
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Apk, APKError> {
        let path = path.as_ref();

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

    /// Reads data from `apk` file.
    ///
    /// ```ignore
    /// let apk = Apk::new("./file.apk").expect("can't analyze apk file");
    /// let (data, compression_method) = apk.read("classes.dex").expect("can't read file");
    /// ```
    #[inline]
    pub fn read(&self, filename: &str) -> Result<(Vec<u8>, FileCompressionType), ZipError> {
        self.zip.read(filename)
    }

    /// Retrieves the list of files that are specified in the central directory (zip).
    ///
    /// ```ignore
    /// let apk = Apk::new("./file.apk").expect("can't analyze apk file");
    /// for file in apk.namelist() {
    ///     println!("{}", file);
    /// }
    /// ```
    #[inline]
    pub fn namelist(&self) -> impl Iterator<Item = &str> + '_ {
        self.zip.namelist()
    }

    /// Converts the internal xml representation of the `AndroidManifest.xml` to a human readable format.
    #[inline]
    pub fn get_xml_string(&self) -> String {
        self.axml.get_xml_string()
    }

    /// Checks if the APK has multiple `classes.dex` files or not.
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

    /// An auxiliary method that allows you to get a value from a reference to a resource.
    ///
    /// It can be a string, a file path, etc., depending on the context in which this function is used.
    ///
    /// ```ignore
    /// let apk = Apk::new("./file.apk").expect("can't analyze apk file");
    /// let app_name = apk.get_resource_value("@string/app_name");
    /// ```
    pub fn get_resource_value(&self, name: &str) -> Option<String> {
        // if not a reference name - return nothing
        if !name.starts_with('@') {
            return None;
        }

        if let Some(arsc) = &self.arsc {
            // safe slice, checked before
            let name = &name[1..];
            return arsc.get_resource_value_by_name(name);
        }

        None
    }

    /// An auxiliary method that allows you to get the attribute value directly from `AndroidManifest.xml`.
    ///
    /// If the value is a link to a resource, it will be automatically resolved to the file name.
    ///
    /// Example of how to get additional information from the `<application>` tag:
    ///
    /// ```ignore
    /// let apk = Apk::new("./file.apk").expect("can't analyze apk file");
    /// apk.get_attribute_value("application", "allowClearUserData")
    /// ```
    #[inline]
    pub fn get_attribute_value(&self, tag: &str, name: &str) -> Option<String> {
        self.axml.get_attribute_value(tag, name, self.arsc.as_ref())
    }

    /// An auxiliary method that allows you to get the value from all attributes from `AndroidManifest.xml`.
    #[inline]
    pub fn get_all_attribute_values<'a>(
        &'a self,
        tag: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> {
        self.axml.get_all_attribute_values(tag, name)
    }

    /// Retrieves the package name declared in the `<manifest>` element.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#package>
    #[inline]
    pub fn get_package_name(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "package", self.arsc.as_ref())
    }

    /// Retrieves the `sharedUserId` attribute from the `<manifest>` element.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uid>
    #[inline]
    pub fn get_shared_user_id(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "sharedUserId", self.arsc.as_ref())
    }

    /// Retrieves the `sharedUserLabel` attribute from the `<manifest>` element.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uidlabel>
    #[inline]
    pub fn get_shared_user_label(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "sharedUserLabel", self.arsc.as_ref())
    }

    /// Retrieves the `sharedUserMaxSdkVersion` attribute from the `<manifest>` element.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#uidmaxsdk>
    #[inline]
    pub fn get_shared_user_max_sdk_version(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "sharedUserMaxSdkVersion", self.arsc.as_ref())
    }

    /// Retrieves the application version code.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#vcode>
    ///
    /// ```ignore
    /// apk.get_version_code() // "2025101912"
    /// ```
    #[inline]
    pub fn get_version_code(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "versionCode", self.arsc.as_ref())
    }

    /// Retrieves the human-readable application version name.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#vname>
    ///
    /// ```ignore
    /// apk.get_version_name() // "1.2.3"
    /// ```
    #[inline]
    pub fn get_version_name(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "versionName", self.arsc.as_ref())
    }

    /// Retrieves the preferred installation location.
    ///
    /// Possible values:
    /// - `"auto"`
    /// - `"internalOnly"`
    /// - `"preferExternal"`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/manifest-element#install>
    #[inline]
    pub fn get_install_location(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "installLocation", self.arsc.as_ref())
    }

    /// Retrieves the `platformBuildVersionCode` from the `<manifest>` element.
    #[inline]
    pub fn get_build_version_code(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "platformBuildVersionCode", self.arsc.as_ref())
    }

    /// Retrieves the `platformBuildVersionName` from the `<manifest>` element.
    #[inline]
    pub fn get_build_version_name(&self) -> Option<String> {
        self.axml
            .get_attribute_value("manifest", "platformBuildVersionName", self.arsc.as_ref())
    }

    /// Extracts the `android:allowTaskReparenting` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#reparent>
    #[inline]
    pub fn get_application_task_reparenting(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "allowTaskReparenting", self.arsc.as_ref())
    }

    /// Extracts the `android:allowBackup` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#allowbackup>
    #[inline]
    pub fn get_application_allow_backup(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "allowBackup", self.arsc.as_ref())
    }

    /// Extracts the `android:appCategory` attribute from `<application>`.
    ///
    /// Possible values include:
    /// - `"accessibility"`
    /// - `"audio"`
    /// - `"game"`
    /// - `"image"`,
    /// - `"maps"`
    /// - `"news"`
    /// - `"productivity"`
    /// - `"social"`
    /// - `"video"`
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
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#debug>
    #[inline]
    pub fn get_application_debuggable(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "debuggable", self.arsc.as_ref())
    }

    /// Extracts and resolve the `android:description` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#desc>
    #[inline]
    pub fn get_application_description(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "description", self.arsc.as_ref())
    }

    /// Extracts and resolves the `android:icon` attribute from `<application>`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#icon>
    #[inline]
    pub fn get_application_icon(&self) -> Option<String> {
        // TODO: need somehow resolve maximum resolution for icon or give option to search density
        self.axml
            .get_attribute_value("application", "icon", self.arsc.as_ref())
    }

    /// Extracts and resolves the `android:label` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#label>
    #[inline]
    pub fn get_application_label(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "label", self.arsc.as_ref())
    }

    /// Extracts and resolves the `android:logo` attribute from `<application>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#logo>
    #[inline]
    pub fn get_application_logo(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "logo", self.arsc.as_ref())
    }

    /// Retrieves all permissions names from `<uses-permission>`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/application-element#nm>
    #[inline]
    pub fn get_application_name(&self) -> Option<String> {
        self.axml
            .get_attribute_value("application", "name", self.arsc.as_ref())
    }

    /// Retrieves all declared permissions from `<uses-permission android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-permission-element>
    #[inline]
    pub fn get_permissions(&self) -> impl Iterator<Item = &str> {
        self.axml
            .get_root_attribute_values("uses-permission", "name")
    }

    /// Retrieves all declared permissions for API level 23 and above from `<uses-permission-sdk-23>` elements.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-permission-sdk-23-element>
    #[inline]
    pub fn get_permissions_sdk23(&self) -> impl Iterator<Item = &str> {
        self.axml
            .get_root_attribute_values("uses-permission-sdk-23", "name")
    }

    /// Extracts the minimum supported SDK version (`minSdkVersion`) from the `<uses-sdk>` element.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#min>
    #[inline]
    pub fn get_min_sdk_version(&self) -> Option<String> {
        self.axml
            .get_attribute_value("uses-sdk", "minSdkVersion", self.arsc.as_ref())
    }

    /// Extracts the target SDK version (`targetSdkVersion`) from the `<uses-sdk>` element.
    ///
    /// Determines the version based on the following algorithm:
    /// 1. Check `targetSdkVersion`;
    /// 2. If empty => check `minSdkVersion`;
    /// 3. If empty => return 1;
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-sdk-element#target>
    #[inline]
    pub fn get_target_sdk_version(&self) -> u32 {
        self.axml
            .get_attribute_value("uses-sdk", "targetSdkVersion", self.arsc.as_ref())
            .or_else(|| self.get_min_sdk_version())
            .and_then(|sdk| sdk.parse::<u32>().ok())
            .unwrap_or(1)
    }

    /// Retrieves the maximum supported SDK version (`maxSdkVersion`) if declared.
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

    /// Retrieves all native libraries declared by `<uses-native-library android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-native-library-element>
    #[inline]
    pub fn get_native_libraries(&self) -> impl Iterator<Item = &str> {
        self.axml
            .get_all_attribute_values("uses-native-library", "name")
    }

    /// Retrieves all hardware or software features declared by `<uses-feature android:name="...">`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element>
    #[inline]
    pub fn get_features(&self) -> impl Iterator<Item = &str> {
        self.axml.get_root_attribute_values("uses-feature", "name")
    }

    /// Checks whether the app is designed to display its user interface on multiple screens inside the vehicle.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    #[inline]
    pub fn is_automotive(&self) -> bool {
        self.get_features()
            .any(|x| x == "android.hardware.type.automotive")
    }

    /// Checks whether the app is designed to show its UI on a television.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    #[inline]
    pub fn is_leanback(&self) -> bool {
        self.get_features()
            .any(|x| x == "android.hardware.type.television" || x == "android.software.leanback")
    }

    /// Checks whether the app is designed to show its UI on a watch.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    #[inline]
    pub fn is_wearable(&self) -> bool {
        self.get_features()
            .any(|x| x == "android.hardware.type.watch")
    }

    /// Checks whether app is designed to show its UI on Chromebooks.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features>
    #[inline]
    pub fn is_chromebook(&self) -> bool {
        self.get_features().any(|x| x == "android.hardware.type.pc")
    }

    /// Retrieves all user defines permissions.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element>
    #[inline]
    pub fn get_declared_permissions<'a>(&'a self) -> impl Iterator<Item = Permission<'a>> {
        // iterates only on childrens, since this tag lives only as a child of the <manifest> tag
        self.axml
            .root
            .childrens()
            .filter(|&el| el.name() == "permission")
            .map(|el| Permission {
                description: el.attr("description"),
                icon: el.attr("icon"),
                label: el.attr("label"),
                name: el.attr("name"),
                permission_group: el.attr("permissionGroup"),
                protection_level: el.attr("protectionLevel"),
            })
    }

    /// Retrieves first main (launchable) activity defined in the manifest.
    ///
    /// A main activity is typically one that has an intent filter with actions `MAIN` and categories `LAUNCHER` or `INFO`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element>
    ///
    /// Resolve logic: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310>
    #[inline]
    pub fn get_main_activity(&self) -> Option<&str> {
        self.axml.get_main_activities().next()
    }

    /// Retrieves all main (launchable) activities defined in the manifest.
    ///
    /// A main activity is typically one that has an intent filter with actions `MAIN` and categories `LAUNCHER` or `INFO`.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element>
    ///
    /// Resolve logic: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310>
    #[inline]
    pub fn get_main_activities(&self) -> impl Iterator<Item = &str> {
        self.axml.get_main_activities()
    }

    /// Retrieves all `<activity>` components declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element>
    #[inline]
    pub fn get_activities<'a>(&'a self) -> impl Iterator<Item = Activity<'a>> {
        // iterates only on childrens, since this tag lives only as a child of the <manifest> tag
        self.axml
            .root
            .descendants()
            .filter(|&el| el.name() == "activity")
            .map(|el| Activity {
                enabled: el.attr("enabled"),
                exported: el.attr("exported"),
                icon: el.attr("icon"),
                label: el.attr("label"),
                name: el.attr("name"),
                parent_activity_name: el.attr("parent_activity_name"),
                permission: el.attr("permission"),
                process: el.attr("process"),
            })
    }

    /// Retrieves all `<service>` components declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element>
    #[inline]
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
                icon: el.attr("icon"),
                isolated_process: el.attr("isolated_process"),
                label: el.attr("label"),
                name: el.attr("name"),
                permission: el.attr("permission"),
                process: el.attr("process"),
                stop_with_task: el.attr("stop_with_task"),
            })
    }

    /// Retrieves all `<receiver>` components declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element>
    #[inline]
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

    /// Retrieves all `<provider>` components declared in the manifest.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element>
    #[inline]
    pub fn get_providers<'a>(&'a self) -> impl Iterator<Item = Provider<'a>> {
        self.axml
            .root
            .descendants()
            .filter(|&el| el.name() == "provider")
            .map(|el| Provider {
                authorities: el.attr("authorities"),
                enabled: el.attr("enabled"),
                direct_boot_aware: el.attr("direct_boot_aware"),
                exported: el.attr("exported"),
                grant_uri_permissions: el.attr("grant_uri_permissions"),
                icon: el.attr("icon"),
                init_order: el.attr("init_order"),
                label: el.attr("label"),
                multiprocess: el.attr("multiprocess"),
                name: el.attr("name"),
                permission: el.attr("permission"),
                process: el.attr("process"),
                read_permission: el.attr("read_permission"),
                syncable: el.attr("syncable"),
                write_permission: el.attr("write_permission"),
            })
    }

    /// Retrieves all APK signing signatures (v1, v2, v3, v3.1, etc).
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
