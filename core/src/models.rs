use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct Application {
    pub allow_task_reparenting: Option<String>,
    pub allow_backup: Option<String>,
    pub app_category: Option<String>,
    pub backup_agent: Option<String>,
    pub debuggable: Option<String>,
    pub description: Option<String>,
    pub label: Option<String>,
    pub name: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ApkJson<'a> {
    pub package_name: Option<String>,

    pub min_sdk_version: Option<String>,

    pub target_sdk_version: Option<String>,

    pub max_sdk_version: Option<String>,

    #[serde(serialize_with = "sorted_set")]
    pub declared_permissions: HashSet<String>,

    pub shared_user_id: Option<String>,

    pub shared_user_label: Option<String>,

    pub shared_user_max_sdk_version: Option<String>,

    pub version_code: Option<String>,

    pub version_name: Option<String>,

    pub install_location: Option<String>,

    #[serde(serialize_with = "sorted_set")]
    pub features: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub permissions: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub permissions_sdk23: HashSet<String>,

    pub application: Application,

    #[serde(serialize_with = "sorted_set")]
    pub main_activities: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub libraries: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub activities: HashSet<String>,

    pub services: HashSet<Service<'a>>,

    #[serde(serialize_with = "sorted_set")]
    pub receivers: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub providers: HashSet<String>,
}

fn sorted_set<S>(set: &HashSet<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut vec: Vec<_> = set.iter().collect();
    vec.sort();
    vec.serialize(serializer)
}

/// Represents xapk manifest.json
#[derive(Deserialize)]
pub struct XAPKManifest {
    /// Defined package name
    pub package_name: String,
}

/// Represents <service> in manifest
///
/// More information: <https://developer.android.com/guide/topics/manifest/service-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Service<'a> {
    // TODO: maybe lazy init resource or something, idk
    // pub icon: Option<String>
    // TODO: maybe lazy init resource or something, idk
    // pub label: Option<String>,
    /// A user-readable description of the service.
    /// Corresponds to the `android:description` attribute.
    pub description: Option<&'a str>,

    /// Indicates whether the service is aware of Direct Boot mode.
    /// Corresponds to the `android:directBootAware` attribute.
    pub direct_boot_aware: Option<&'a str>,

    /// Specifies whether the service can be instantiated by the system.
    /// Corresponds to the `android:enabled` attribute.
    pub enabled: Option<&'a str>,

    /// Defines whether the service can be used by other applications.
    /// Corresponds to the `android:exported` attribute.
    pub exported: Option<&'a str>,

    /// Lists the types of foreground services this service can run as.
    /// Corresponds to the `android:foregroundServiceType` attribute.
    pub foreground_service_type: Option<&'a str>,

    /// Indicates whether the service runs in an isolated process.
    /// Corresponds to the `android:isolatedProcess` attribute.
    pub isolated_process: Option<&'a str>,

    /// The fully qualified name of the service class that implements the service.
    /// Corresponds to the `android:name` attribute.
    pub name: Option<&'a str>,

    /// The name of a permission that clients must hold to use this service.
    /// Corresponds to the `android:permission` attribute.
    pub permission: Option<&'a str>,

    /// The name of the process where the service should run.
    /// Corresponds to the `android:process` attribute.
    pub process: Option<&'a str>,

    /// Indicates whether the service should be stopped when its task is removed.
    /// Corresponds to the `android:stopWithTask` attribute.
    pub stop_with_task: Option<&'a str>,
}
