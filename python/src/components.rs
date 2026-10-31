//! Python classes for the manifest elements: activities, services, receivers,
//! providers, permissions and attributions.
//!
//! The core models borrow their strings from the parsed manifest; a Python
//! object needs its own, so each class here is an owned copy of a model.

use std::fmt;

use ::apk_info::models::{
    Activity as ApkActivity, ActivityAlias as ApkActivityAlias, Attribution as ApkAttribution,
    IntentFilter as ApkIntentFilter, Permission as ApkPermission, Provider as ApkProvider,
    Receiver as ApkReceiver, Service as ApkService,
};
use pyo3::prelude::*;

/// Declares a Python class that copies a core model.
///
/// Optional attributes come first, then, after `;`, the list attributes with
/// the class of their items. The class gets a getter per field, a `From`
/// conversion from the model, and a repr that skips unset attributes and
/// empty lists: `Activity(name="a.Main", intent_filters=[...])`.
macro_rules! model {
    (
        $(#[$meta:meta])*
        $name:ident from $source:ident {
            $($field:ident),* $(,)?
            $(; $($list:ident: Vec<$item:ident>),+ $(,)?)?
        }
    ) => {
        $(#[$meta])*
        #[pyclass(frozen, from_py_object, module = "apk_info._apk_info")]
        #[derive(Clone, Hash, PartialEq, Eq)]
        pub(crate) struct $name {
            $(
                #[pyo3(get)]
                $field: Option<String>,
            )*
            $($(
                #[pyo3(get)]
                $list: Vec<$item>,
            )+)?
        }

        impl From<$source<'_>> for $name {
            fn from(model: $source<'_>) -> Self {
                Self {
                    $($field: model.$field.map(String::from),)*
                    $($($list: model.$list.into_iter().map($item::from).collect(),)+)?
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut parts: Vec<String> = Vec::new();
                $(
                    if let Some(value) = &self.$field {
                        parts.push(format!(concat!(stringify!($field), "={:?}"), value));
                    }
                )*
                $($(
                    if !self.$list.is_empty() {
                        parts.push(format!(concat!(stringify!($list), "={:?}"), self.$list));
                    }
                )+)?
                write!(f, concat!(stringify!($name), "({})"), parts.join(", "))
            }
        }

        #[pymethods]
        impl $name {
            fn __repr__(&self) -> String {
                format!("{self:?}")
            }
        }
    };
}

model! {
    /// An `<intent-filter>` of a component.
    IntentFilter from ApkIntentFilter {
        ; actions: Vec<String>, categories: Vec<String>
    }
}

model! {
    /// An `<activity>` element.
    Activity from ApkActivity {
        enabled, exported, icon, label, name, parent_activity_name, permission, process;
        intent_filters: Vec<IntentFilter>
    }
}

model! {
    /// An `<activity-alias>` element.
    ActivityAlias from ApkActivityAlias {
        enabled, exported, icon, label, name, permission, target_activity;
        intent_filters: Vec<IntentFilter>
    }
}

model! {
    /// A `<permission>` the app declares.
    Permission from ApkPermission {
        description, icon, label, name, permission_group, protection_level
    }
}

model! {
    /// A `<provider>` element.
    Provider from ApkProvider {
        authorities, enabled, direct_boot_aware, exported, grant_uri_permissions, icon,
        init_order, label, multiprocess, name, permission, process, read_permission,
        syncable, write_permission
    }
}

model! {
    /// A `<service>` element.
    Service from ApkService {
        description, direct_boot_aware, enabled, exported, foreground_service_type, icon,
        isolated_process, label, name, permission, process, stop_with_task;
        intent_filters: Vec<IntentFilter>
    }
}

model! {
    /// A `<receiver>` element.
    Receiver from ApkReceiver {
        direct_boot_aware, enabled, exported, icon, label, name, permission, process;
        intent_filters: Vec<IntentFilter>
    }
}

model! {
    /// An `<attribution>` element.
    Attribution from ApkAttribution {
        tag, label
    }
}
