//! Abstractions over `manifest` tags.

use serde::{Deserialize, Serialize};

/// Represents xapk manifest.json
#[derive(Deserialize)]
pub struct XAPKManifest {
    /// Defined package name
    pub package_name: String,
}

/// Represents `<meta-data>` in manifest
///
/// See: <https://developer.android.com/guide/topics/manifest/meta-data-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MetaData<'a> {
    /// A unique name for the item
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/meta-data-element#nm>
    pub name: Option<&'a str>,

    /// A reference to a resource.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/meta-data-element#rsrc>
    pub resource: Option<&'a str>,

    /// The value assigned to the item.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/meta-data-element#val>
    pub value: Option<&'a str>,
}

/// Represents `<activity>` in manifest
///
/// More information: <https://developer.android.com/guide/topics/manifest/activity-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Activity<'a> {
    /// Whether the activity can be instantiated by the system.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#enabled>
    pub enabled: Option<&'a str>,

    /// Whether the activity can be launched by components of other applications
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#exported>
    pub exported: Option<&'a str>,

    /// An icon representing the activity.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#icon>
    pub icon: Option<&'a str>,

    /// A user-readable label for the activity.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#label>
    pub label: Option<&'a str>,

    /// The name of the class that implements the activity, a subclass of `Activity`
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#nm>
    pub name: Option<&'a str>,

    /// The class name of the logical parent of the activity.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#parent>
    pub parent_activity_name: Option<&'a str>,

    /// The name of a permission that clients must have to launch the activity or otherwise get it to respond to an intent.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#prmsn>
    pub permission: Option<&'a str>,

    /// The name of the process in which the activity runs.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/activity-element#proc>
    pub process: Option<&'a str>,
}

/// Represents `<permission>` in manifest
///
/// More information: <https://developer.android.com/guide/topics/manifest/permission-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Permission<'a> {
    /// A user-readable description of the permission that is longer and more informative than the label.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element#desc>
    pub description: Option<&'a str>,

    /// A reference to a drawable resource for an icon that represents the permission.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element#icon>
    pub icon: Option<&'a str>,

    /// A user-readable name for the permission.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element#label>
    pub label: Option<&'a str>,

    /// The name to be used in code to refer to the permission, such as in a `<uses-permission>` element
    /// or the permission attributes of application components.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element#nm>
    pub name: Option<&'a str>,

    /// Assigns this permission to a group. The value of this attribute is the name of the group,
    /// which is declared with the `<permission-group>` element in this or another application.
    /// If this attribute isn't set, the permission doesn't belong to a group.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element#pgroup>
    pub permission_group: Option<&'a str>,

    /// Characterizes the potential risk implied in the permission and indicates the procedure for
    /// the system to follow when determining whether to grant the permission to an application
    /// requesting it.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/permission-element#plevel>
    pub protection_level: Option<&'a str>,
}

/// Represents `<provider>` in manifest.
///
/// More information: <https://developer.android.com/guide/topics/manifest/provider-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Provider<'a> {
    /// A list of URI authorities identifying data offered by the content provider.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#auth>
    pub authorities: Option<&'a str>,

    /// Whether the content provider can be instantiated by the system.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#enabled>
    pub enabled: Option<&'a str>,

    /// Whether the content provider is Direct Boot aware.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#directBootAware>
    pub direct_boot_aware: Option<&'a str>,

    /// Whether the content provider is available for other applications to use.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#exported>
    pub exported: Option<&'a str>,

    /// Whether temporary URI permissions can be granted to access the provider’s data.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#granturi>
    pub grant_uri_permissions: Option<&'a str>,

    /// An icon representing the content provider.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#icon>
    pub icon: Option<&'a str>,

    /// The order in which the provider is instantiated relative to others in the same process.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#init>
    pub init_order: Option<&'a str>,

    /// A user-readable label for the content provider.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#label>
    pub label: Option<&'a str>,

    /// Whether multiple instances of the provider are created in multiprocess apps.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#multiprocess>
    pub multiprocess: Option<&'a str>,

    /// The name of the class implementing the content provider.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#nm>
    pub name: Option<&'a str>,

    /// A permission required to read or write the provider’s data.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#prmsn>
    pub permission: Option<&'a str>,

    /// The name of the process where the provider runs.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#proc>
    pub process: Option<&'a str>,

    /// A permission that clients must have to read the provider’s data.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#read>
    pub read_permission: Option<&'a str>,

    /// Whether the provider’s data can be synchronized with a server.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#syncable>
    pub syncable: Option<&'a str>,

    /// A permission that clients must have to modify the provider’s data.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/provider-element#write>
    pub write_permission: Option<&'a str>,
}

/// Represents `<service>` in manifest
///
/// More information: <https://developer.android.com/guide/topics/manifest/service-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Service<'a> {
    /// A user-readable description of the service.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#desc>
    pub description: Option<&'a str>,

    /// Indicates whether the service is aware of Direct Boot mode.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#directBootAware>
    pub direct_boot_aware: Option<&'a str>,

    /// Specifies whether the service can be instantiated by the system.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#enabled>
    pub enabled: Option<&'a str>,

    /// Defines whether the service can be used by other applications.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#exported>
    pub exported: Option<&'a str>,

    /// Lists the types of foreground services this service can run as.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#foregroundservicetype>
    pub foreground_service_type: Option<&'a str>,

    /// An icon representing the service.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#icon>
    pub icon: Option<&'a str>,

    /// Indicates whether the service runs in an isolated process.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#isolated>
    pub isolated_process: Option<&'a str>,

    /// A user-readable name for the service.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#label>
    pub label: Option<&'a str>,

    /// The fully qualified name of the service class that implements the service.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#nm>
    pub name: Option<&'a str>,

    /// The name of a permission that clients must hold to use this service.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#prmsn>
    pub permission: Option<&'a str>,

    /// The name of the process where the service should run.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#proc>
    pub process: Option<&'a str>,

    /// Indicates whether the service should be stopped when its task is removed.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/service-element#stopWithTask>
    pub stop_with_task: Option<&'a str>,
}

/// Represents `<receiver>` in manifest
///
/// More information: <https://developer.android.com/guide/topics/manifest/receiver-element>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Receiver<'a> {
    /// Indicates whether the broadcast receiver is direct boot aware.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#directBootAware>
    pub direct_boot_aware: Option<&'a str>,

    /// Whether the broadcast receiver can be instantiated by the system.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#enabled>
    pub enabled: Option<&'a str>,

    /// Specifies whether the broadcast receiver is accessible to other applications.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#exported>
    pub exported: Option<&'a str>,

    /// An icon that represents the broadcast receiver in the user interface.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#icon>
    pub icon: Option<&'a str>,

    /// A user-readable label for the broadcast receiver.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#label>
    pub label: Option<&'a str>,

    /// The fully qualified name of the broadcast receiver class that implements the receiver.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#nm>
    pub name: Option<&'a str>,

    /// The name of a permission that broadcasters must hold to send messages to this receiver.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#prmsn>
    pub permission: Option<&'a str>,

    /// The name of the process in which the broadcast receiver should run.
    ///
    /// See: <https://developer.android.com/guide/topics/manifest/receiver-element#proc>
    pub process: Option<&'a str>,
}
