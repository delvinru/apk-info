//! The `APK` class: a thin layer over [`apk_info::Apk`].

use std::collections::HashSet;
use std::path::PathBuf;

use ::apk_info::Apk as ApkRust;
use ::apk_info_zip::{FileCompressionType, Signature as ZipSignature, ZipEntry};
use pyo3::exceptions::{PyFileNotFoundError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyString;

use crate::APKError;
use crate::anomaly::Anomaly;
use crate::components::{
    Activity, ActivityAlias, Attribution, Permission, Provider, Receiver, Service,
};
use crate::signature::Signature;

#[pyclass(name = "APK", frozen, module = "apk_info._apk_info")]
pub(crate) struct Apk {
    apkrs: ApkRust,
}

impl Apk {
    /// The base APK of a `xapk`/`apkm`/`apks` container, or the APK itself.
    fn base_zip(&self) -> PyResult<&ZipEntry> {
        self.apkrs
            .get_base_zip()
            .map_err(|e| APKError::new_err(e.to_string()))
    }
}

fn compression_hint(kind: FileCompressionType) -> &'static str {
    match kind {
        FileCompressionType::Stored => "stored",
        FileCompressionType::Deflated => "deflated",
        FileCompressionType::StoredTampered => "stored_tampered",
        FileCompressionType::DeflatedTampered => "deflated_tampered",
    }
}

fn signatures(result: Result<Vec<ZipSignature>, impl std::fmt::Debug>) -> PyResult<Vec<Signature>> {
    Ok(result
        .map_err(|e| APKError::new_err(format!("failed to get signatures: {e:?}")))?
        .into_iter()
        .map(Signature::from)
        .collect())
}

/// Generates the `#[pymethods]` block from three parts:
///
/// - `delegate`: methods that return the core method's value as is;
/// - `collect`: methods that collect the core method's iterator, converting
///   each item with `Into`, e.g. a core `Activity<'_>` into [`Activity`];
/// - the methods written out by hand.
///
/// pyo3 allows one `#[pymethods]` block per class, so all go into the same.
macro_rules! apk_methods {
    (
        delegate {
            $($delegate:ident($($darg:ident: $dty:ty),*) -> $dret:ty;)*
        }
        collect {
            $($collect:ident($($carg:ident: $cty:ty),*) -> $cret:ty;)*
        }
        $($methods:tt)*
    ) => {
        #[pymethods]
        impl Apk {
            $(
                fn $delegate(&self, $($darg: $dty),*) -> $dret {
                    self.apkrs.$delegate($($darg),*)
                }
            )*

            $(
                fn $collect(&self, $($carg: $cty),*) -> $cret {
                    self.apkrs.$collect($($carg),*).map(Into::into).collect()
                }
            )*

            $($methods)*
        }
    };
}

apk_methods! {
    delegate {
        get_package_name() -> Option<String>;
        get_shared_user_id() -> Option<String>;
        get_shared_user_label() -> Option<String>;
        get_shared_user_max_sdk_version() -> Option<String>;
        get_version_code() -> Option<String>;
        get_version_name() -> Option<String>;
        get_build_version_code() -> Option<String>;
        get_build_version_name() -> Option<String>;
        get_compile_sdk_version() -> Option<String>;
        get_compile_sdk_version_codename() -> Option<String>;
        get_install_location() -> Option<String>;
        get_application_task_reparenting() -> Option<String>;
        get_application_allow_backup() -> Option<String>;
        get_application_category() -> Option<String>;
        get_application_backup_agent() -> Option<String>;
        get_application_debuggable() -> Option<String>;
        get_application_description() -> Option<String>;
        get_application_icon() -> Option<String>;
        get_application_logo() -> Option<String>;
        get_application_label() -> Option<String>;
        get_application_name() -> Option<String>;
        get_min_sdk_version() -> Option<String>;
        get_max_sdk_version() -> Option<String>;
        get_target_sdk_version() -> u32;
        get_main_activity() -> Option<&str>;
        get_supported_abis() -> Vec<String>;
        get_xml_string() -> String;
        get_resource_value(name: &str) -> Option<String>;
        get_attribute_value(tag: &str, name: &str) -> Option<String>;
        is_multidex() -> bool;
        is_automotive() -> bool;
        is_leanback() -> bool;
        is_wearable() -> bool;
        is_chromebook() -> bool;
        is_xr() -> bool;
    }

    collect {
        get_permissions() -> HashSet<&str>;
        get_permissions_sdk23() -> HashSet<&str>;
        get_libraries() -> HashSet<&str>;
        get_native_libraries() -> HashSet<&str>;
        get_features() -> HashSet<&str>;
        // a list, not a set: the order of the manifest is kept
        get_main_activities() -> Vec<&str>;
        get_activities() -> Vec<Activity>;
        get_activity_aliases() -> Vec<ActivityAlias>;
        get_services() -> Vec<Service>;
        get_receivers() -> Vec<Receiver>;
        get_providers() -> Vec<Provider>;
        get_declared_permissions() -> HashSet<Permission>;
        get_attributions() -> HashSet<Attribution>;
    }

    #[new]
    fn new(path: &Bound<'_, PyAny>) -> PyResult<Apk> {
        let py = path.py();
        let path = match path.extract::<&str>() {
            Ok(path) => PathBuf::from(path),
            Err(_) => path
                .extract::<PathBuf>()
                .map_err(|_| PyTypeError::new_err("expected str | PurePath"))?,
        };
        if !path.exists() {
            return Err(PyFileNotFoundError::new_err(format!(
                "file not found: {path:?}"
            )));
        }

        // parsing is pure Rust: other Python threads run meanwhile
        let apkrs = py
            .detach(|| ApkRust::new(&path))
            .map_err(|e| APKError::new_err(e.to_string()))?;

        Ok(Apk { apkrs })
    }

    #[pyo3(signature = (filename, base = false))]
    fn read(&self, filename: &Bound<'_, PyString>, base: bool) -> PyResult<(Vec<u8>, String)> {
        let name: &str = filename
            .extract()
            .map_err(|_| PyValueError::new_err("bad filename"))?;

        // decompression can take a while for a large entry
        let py = filename.py();
        let result = if base {
            let zip = self.base_zip()?;
            py.detach(|| zip.read(name))
        } else {
            py.detach(|| self.apkrs.read(name))
        };

        result
            .map(|(data, compression)| (data, compression_hint(compression).to_owned()))
            .map_err(|e| APKError::new_err(e.to_string()))
    }

    #[pyo3(signature = (base = false))]
    fn namelist(&self, base: bool) -> PyResult<Vec<&str>> {
        if base {
            Ok(self.base_zip()?.namelist().collect())
        } else {
            Ok(self.apkrs.namelist().collect())
        }
    }

    fn get_all_attribute_values<'a>(&'a self, tag: &'a str, name: &'a str) -> Vec<&'a str> {
        self.apkrs.get_all_attribute_values(tag, name).collect()
    }

    fn get_signatures(&self, py: Python<'_>) -> PyResult<Vec<Signature>> {
        // reads and parses the signing block and the certificates
        signatures(py.detach(|| self.apkrs.get_signatures()))
    }

    fn get_container_signatures(&self, py: Python<'_>) -> PyResult<Vec<Signature>> {
        signatures(py.detach(|| self.apkrs.get_container_signatures()))
    }

    fn anomalies(&self, py: Python<'_>) -> Vec<Anomaly> {
        // reads the local header of every zip entry
        py.detach(|| self.apkrs.anomalies())
            .into_iter()
            .map(Anomaly::from)
            .collect()
    }

    fn is_tampered(&self, py: Python<'_>) -> bool {
        py.detach(|| self.apkrs.is_tampered())
    }
}
