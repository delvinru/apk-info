use std::collections::HashSet;
use std::path::PathBuf;

use ::apk_info::Apk as ApkRust;
use ::apk_info::models::{
    Activity as ApkActivity, Permission as ApkPermission, Provider as ApkProvider,
    Receiver as ApkReceiver, Service as ApkService,
};
use ::apk_info_zip::{CertificateInfo as ZipCertificateInfo, Signature as ZipSignature};
use pyo3::exceptions::{PyException, PyFileNotFoundError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyString;
use pyo3::{Bound, PyAny, PyResult, create_exception, pyclass, pymethods};

create_exception!(m, APKError, PyException, "Got error while parsing apk");

#[pyclass(eq, frozen, module = "apk_info._apk_info")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CertificateInfo {
    #[pyo3(get)]
    pub serial_number: String,

    #[pyo3(get)]
    pub subject: String,

    #[pyo3(get)]
    pub valid_from: String,

    #[pyo3(get)]
    pub valid_until: String,

    #[pyo3(get)]
    pub signature_type: String,

    #[pyo3(get)]
    pub md5_fingerprint: String,

    #[pyo3(get)]
    pub sha1_fingerprint: String,

    #[pyo3(get)]
    pub sha256_fingerprint: String,
}

impl From<ZipCertificateInfo> for CertificateInfo {
    fn from(certificate: ZipCertificateInfo) -> Self {
        Self {
            serial_number: certificate.serial_number,
            subject: certificate.subject,
            valid_from: certificate.valid_from,
            valid_until: certificate.valid_until,
            signature_type: certificate.signature_type,
            md5_fingerprint: certificate.md5_fingerprint,
            sha1_fingerprint: certificate.sha1_fingerprint,
            sha256_fingerprint: certificate.sha256_fingerprint,
        }
    }
}

#[pymethods]
impl CertificateInfo {
    fn __repr__(&self) -> String {
        format!(
            "CertificateInfo(serial_number='{}', subject='{}', valid_from='{}', valid_until='{}', signature_type='{}', md5_fingerprint='{}', sha1_fingerprint='{}', sha256_fingerprint='{}')",
            self.serial_number,
            self.subject,
            self.valid_from,
            self.valid_until,
            self.signature_type,
            self.md5_fingerprint,
            self.sha1_fingerprint,
            self.sha256_fingerprint
        )
    }
}

#[pyclass(eq, frozen, module = "apk_info._apk_info")]
#[derive(PartialEq, Eq, Hash)]
enum Signature {
    V1 { certificates: Vec<CertificateInfo> },
    V2 { certificates: Vec<CertificateInfo> },
    V3 { certificates: Vec<CertificateInfo> },
    V31 { certificates: Vec<CertificateInfo> },
    StampBlockV1 { certificate: CertificateInfo },
    StampBlockV2 { certificate: CertificateInfo },
    ApkChannelBlock { value: String },
}

impl Signature {
    fn from<'py>(py: Python<'py>, signature: ZipSignature) -> Option<Bound<'py, Signature>> {
        match signature {
            ZipSignature::V1(v) => Signature::V1 {
                certificates: v.into_iter().map(CertificateInfo::from).collect(),
            }
            .into_pyobject(py)
            .ok(),
            ZipSignature::V2(v) => Signature::V2 {
                certificates: v.into_iter().map(CertificateInfo::from).collect(),
            }
            .into_pyobject(py)
            .ok(),
            ZipSignature::V3(v) => Signature::V3 {
                certificates: v.into_iter().map(CertificateInfo::from).collect(),
            }
            .into_pyobject(py)
            .ok(),
            ZipSignature::V31(v) => Signature::V31 {
                certificates: v.into_iter().map(CertificateInfo::from).collect(),
            }
            .into_pyobject(py)
            .ok(),
            ZipSignature::StampBlockV1(v) => Signature::StampBlockV1 {
                certificate: v.into(),
            }
            .into_pyobject(py)
            .ok(),
            ZipSignature::StampBlockV2(v) => Signature::StampBlockV2 {
                certificate: v.into(),
            }
            .into_pyobject(py)
            .ok(),
            ZipSignature::ApkChannelBlock(v) => Signature::ApkChannelBlock { value: v }
                .into_pyobject(py)
                .ok(),
            _ => None,
        }
    }
}

#[pymethods]
impl Signature {
    fn __repr__(&self) -> String {
        match self {
            Signature::V1 { certificates } => {
                format!("Signature.V1(certificates={:?})", certificates)
            }
            Signature::V2 { certificates } => {
                format!("Signature.V2(certificates={:?})", certificates)
            }
            Signature::V3 { certificates } => {
                format!("Signature.V3(certificates={:?})", certificates)
            }
            Signature::V31 { certificates } => {
                format!("Signature.V31(certificates={:?})", certificates)
            }
            Signature::StampBlockV1 { certificate } => {
                format!("Signature.StampBlockV1(certificate={:?})", certificate)
            }
            Signature::StampBlockV2 { certificate } => {
                format!("Signature.StampBlockV2(certificate={:?})", certificate)
            }
            Signature::ApkChannelBlock { value } => {
                format!("Signature.ApkChannelBlock(channel='{}')", value)
            }
        }
    }
}

#[pyclass(frozen, module = "apk_info._apk_info")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Activity {
    #[pyo3(get)]
    enabled: Option<String>,
    #[pyo3(get)]
    exported: Option<String>,
    #[pyo3(get)]
    icon: Option<String>,
    #[pyo3(get)]
    label: Option<String>,
    #[pyo3(get)]
    name: Option<String>,
    #[pyo3(get)]
    parent_activity_name: Option<String>,
    #[pyo3(get)]
    permission: Option<String>,
    #[pyo3(get)]
    process: Option<String>,
}

impl<'a> From<ApkActivity<'a>> for Activity {
    fn from(activity: ApkActivity<'a>) -> Self {
        Activity {
            enabled: activity.enabled.map(String::from),
            exported: activity.exported.map(String::from),
            icon: activity.icon.map(String::from),
            label: activity.label.map(String::from),
            name: activity.name.map(String::from),
            parent_activity_name: activity.parent_activity_name.map(String::from),
            permission: activity.permission.map(String::from),
            process: activity.process.map(String::from),
        }
    }
}
#[pymethods]
impl Activity {
    fn __repr__(&self) -> String {
        let mut parts = Vec::with_capacity(16);
        macro_rules! push_field {
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    parts.push(format!(concat!(stringify!($field), "={:?}"), v));
                }
            };
        }
        push_field!(enabled);
        push_field!(exported);
        push_field!(icon);
        push_field!(label);
        push_field!(name);
        push_field!(parent_activity_name);
        push_field!(permission);
        push_field!(process);

        format!("Activity({})", parts.join(", "))
    }
}

#[pyclass(frozen, module = "apk_info._apk_info")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Permission {
    #[pyo3(get)]
    description: Option<String>,
    #[pyo3(get)]
    icon: Option<String>,
    #[pyo3(get)]
    label: Option<String>,
    #[pyo3(get)]
    name: Option<String>,
    #[pyo3(get)]
    permission_group: Option<String>,
    #[pyo3(get)]
    protection_level: Option<String>,
}

impl<'a> From<ApkPermission<'a>> for Permission {
    fn from(permission: ApkPermission<'a>) -> Self {
        Permission {
            description: permission.description.map(String::from),
            icon: permission.icon.map(String::from),
            label: permission.label.map(String::from),
            name: permission.name.map(String::from),
            permission_group: permission.permission_group.map(String::from),
            protection_level: permission.protection_level.map(String::from),
        }
    }
}

#[pymethods]
impl Permission {
    fn __repr__(&self) -> String {
        let mut parts = Vec::with_capacity(16);
        macro_rules! push_field {
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    parts.push(format!(concat!(stringify!($field), "={:?}"), v));
                }
            };
        }
        push_field!(description);
        push_field!(icon);
        push_field!(label);
        push_field!(name);
        push_field!(permission_group);
        push_field!(protection_level);

        format!("Permission({})", parts.join(", "))
    }
}

#[pyclass(frozen, module = "apk_info._apk_info")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Provider {
    #[pyo3(get)]
    pub authorities: Option<String>,
    #[pyo3(get)]
    pub enabled: Option<String>,
    #[pyo3(get)]
    pub direct_boot_aware: Option<String>,
    #[pyo3(get)]
    pub exported: Option<String>,
    #[pyo3(get)]
    pub grant_uri_permissions: Option<String>,
    #[pyo3(get)]
    pub icon: Option<String>,
    #[pyo3(get)]
    pub init_order: Option<String>,
    #[pyo3(get)]
    pub label: Option<String>,
    #[pyo3(get)]
    pub multiprocess: Option<String>,
    #[pyo3(get)]
    pub name: Option<String>,
    #[pyo3(get)]
    pub permission: Option<String>,
    #[pyo3(get)]
    pub process: Option<String>,
    #[pyo3(get)]
    pub read_permission: Option<String>,
    #[pyo3(get)]
    pub syncable: Option<String>,
    #[pyo3(get)]
    pub write_permission: Option<String>,
}

impl<'a> From<ApkProvider<'a>> for Provider {
    fn from(provider: ApkProvider<'a>) -> Self {
        Provider {
            authorities: provider.authorities.map(String::from),
            enabled: provider.enabled.map(String::from),
            direct_boot_aware: provider.direct_boot_aware.map(String::from),
            exported: provider.exported.map(String::from),
            grant_uri_permissions: provider.grant_uri_permissions.map(String::from),
            icon: provider.icon.map(String::from),
            init_order: provider.init_order.map(String::from),
            label: provider.label.map(String::from),
            multiprocess: provider.multiprocess.map(String::from),
            name: provider.name.map(String::from),
            permission: provider.permission.map(String::from),
            process: provider.process.map(String::from),
            read_permission: provider.read_permission.map(String::from),
            syncable: provider.syncable.map(String::from),
            write_permission: provider.write_permission.map(String::from),
        }
    }
}

#[pymethods]
impl Provider {
    fn __repr__(&self) -> String {
        let mut parts = Vec::with_capacity(16);
        macro_rules! push_field {
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    parts.push(format!(concat!(stringify!($field), "={:?}"), v));
                }
            };
        }

        push_field!(authorities);
        push_field!(enabled);
        push_field!(direct_boot_aware);
        push_field!(exported);
        push_field!(grant_uri_permissions);
        push_field!(icon);
        push_field!(init_order);
        push_field!(label);
        push_field!(multiprocess);
        push_field!(name);
        push_field!(permission);
        push_field!(process);
        push_field!(read_permission);
        push_field!(syncable);
        push_field!(write_permission);

        format!("Provider({})", parts.join(", "))
    }
}

#[pyclass(frozen, module = "apk_info._apk_info")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Service {
    #[pyo3(get)]
    description: Option<String>,
    #[pyo3(get)]
    direct_boot_aware: Option<String>,
    #[pyo3(get)]
    enabled: Option<String>,
    #[pyo3(get)]
    exported: Option<String>,
    #[pyo3(get)]
    foreground_service_type: Option<String>,
    #[pyo3(get)]
    icon: Option<String>,
    #[pyo3(get)]
    isolated_process: Option<String>,
    #[pyo3(get)]
    label: Option<String>,
    #[pyo3(get)]
    name: Option<String>,
    #[pyo3(get)]
    permission: Option<String>,
    #[pyo3(get)]
    process: Option<String>,
    #[pyo3(get)]
    stop_with_task: Option<String>,
}

impl<'a> From<ApkService<'a>> for Service {
    fn from(service: ApkService<'a>) -> Self {
        Service {
            description: service.description.map(String::from),
            direct_boot_aware: service.direct_boot_aware.map(String::from),
            enabled: service.enabled.map(String::from),
            exported: service.exported.map(String::from),
            foreground_service_type: service.foreground_service_type.map(String::from),
            icon: service.icon.map(String::from),
            isolated_process: service.isolated_process.map(String::from),
            label: service.label.map(String::from),
            name: service.name.map(String::from),
            permission: service.permission.map(String::from),
            process: service.process.map(String::from),
            stop_with_task: service.stop_with_task.map(String::from),
        }
    }
}

#[pymethods]
impl Service {
    fn __repr__(&self) -> String {
        let mut parts = Vec::with_capacity(16);
        macro_rules! push_field {
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    parts.push(format!(concat!(stringify!($field), "={:?}"), v));
                }
            };
        }
        push_field!(description);
        push_field!(direct_boot_aware);
        push_field!(enabled);
        push_field!(exported);
        push_field!(foreground_service_type);
        push_field!(isolated_process);
        push_field!(name);
        push_field!(permission);
        push_field!(process);
        push_field!(stop_with_task);

        format!("Service({})", parts.join(", "))
    }
}

#[pyclass(frozen, module = "apk_info._apk_info")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Receiver {
    #[pyo3(get)]
    pub direct_boot_aware: Option<String>,

    #[pyo3(get)]
    pub enabled: Option<String>,

    #[pyo3(get)]
    pub exported: Option<String>,

    #[pyo3(get)]
    pub icon: Option<String>,

    #[pyo3(get)]
    pub label: Option<String>,

    #[pyo3(get)]
    pub name: Option<String>,

    #[pyo3(get)]
    pub permission: Option<String>,

    #[pyo3(get)]
    pub process: Option<String>,
}

impl<'a> From<ApkReceiver<'a>> for Receiver {
    fn from(receiver: ApkReceiver<'a>) -> Self {
        Receiver {
            direct_boot_aware: receiver.direct_boot_aware.map(String::from),
            enabled: receiver.enabled.map(String::from),
            exported: receiver.exported.map(String::from),
            icon: receiver.icon.map(String::from),
            label: receiver.label.map(String::from),
            name: receiver.name.map(String::from),
            permission: receiver.permission.map(String::from),
            process: receiver.process.map(String::from),
        }
    }
}

#[pymethods]
impl Receiver {
    fn __repr__(&self) -> String {
        let mut parts = Vec::with_capacity(16);
        macro_rules! push_field {
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    parts.push(format!(concat!(stringify!($field), "={:?}"), v));
                }
            };
        }
        push_field!(direct_boot_aware);
        push_field!(enabled);
        push_field!(exported);
        push_field!(icon);
        push_field!(label);
        push_field!(name);
        push_field!(permission);
        push_field!(process);

        format!("Receiver({})", parts.join(", "))
    }
}

#[pyclass(name = "APK", unsendable, module = "apk_info._apk_info")]
struct Apk {
    apkrs: ApkRust,
}

#[pymethods]
impl Apk {
    #[new]
    pub fn new(path: &Bound<'_, PyAny>) -> PyResult<Apk> {
        let resolved: Option<PathBuf> = if let Ok(s) = path.extract::<&str>() {
            Some(PathBuf::from(s))
        } else {
            path.extract::<PathBuf>().ok()
        };

        let path = resolved.ok_or_else(|| PyTypeError::new_err("expected str | Path"))?;
        if !path.exists() {
            return Err(PyFileNotFoundError::new_err(format!(
                "file not found: {:?}",
                path
            )));
        }

        let apkrs = ApkRust::new(&path).map_err(|e| APKError::new_err(e.to_string()))?;

        Ok(Apk { apkrs })
    }

    pub fn read(&self, filename: &Bound<'_, PyString>) -> PyResult<Vec<u8>> {
        let filename = match filename.extract::<&str>() {
            Ok(name) => name,
            Err(_) => return Err(PyValueError::new_err("bad filename")),
        };

        match self.apkrs.read(filename) {
            Ok((data, _)) => {
                // TODO: return compression type
                Ok(data)
            }
            Err(e) => Err(APKError::new_err(e.to_string())),
        }
    }

    pub fn namelist(&self) -> Vec<&str> {
        self.apkrs.namelist().collect()
    }

    pub fn is_multidex(&self) -> bool {
        self.apkrs.is_multidex()
    }

    pub fn get_xml_string(&self) -> String {
        self.apkrs.get_xml_string()
    }

    pub fn get_resource_value(&self, name: &str) -> Option<String> {
        self.apkrs.get_resource_value(name)
    }

    pub fn get_attribute_value(&self, tag: &str, name: &str) -> Option<String> {
        self.apkrs.get_attribute_value(tag, name)
    }

    pub fn get_all_attribute_values<'a>(&'a self, tag: &'a str, name: &'a str) -> Vec<&'a str> {
        self.apkrs.get_all_attribute_values(tag, name).collect()
    }

    pub fn get_package_name(&self) -> Option<String> {
        self.apkrs.get_package_name()
    }

    pub fn get_shared_user_id(&self) -> Option<String> {
        self.apkrs.get_shared_user_id()
    }

    pub fn get_shared_user_label(&self) -> Option<String> {
        self.apkrs.get_shared_user_label()
    }

    pub fn get_shared_user_max_sdk_version(&self) -> Option<String> {
        self.apkrs.get_shared_user_max_sdk_version()
    }

    pub fn get_version_code(&self) -> Option<String> {
        self.apkrs.get_version_code()
    }

    pub fn get_version_name(&self) -> Option<String> {
        self.apkrs.get_version_name()
    }

    pub fn get_build_version_code(&self) -> Option<String> {
        self.apkrs.get_build_version_code()
    }

    pub fn get_build_version_name(&self) -> Option<String> {
        self.apkrs.get_build_version_name()
    }

    pub fn get_install_location(&self) -> Option<String> {
        self.apkrs.get_install_location()
    }

    pub fn get_application_task_reparenting(&self) -> Option<String> {
        self.apkrs.get_application_task_reparenting()
    }

    pub fn get_application_allow_backup(&self) -> Option<String> {
        self.apkrs.get_application_allow_backup()
    }

    pub fn get_application_category(&self) -> Option<String> {
        self.apkrs.get_application_category()
    }

    pub fn get_application_backup_agent(&self) -> Option<String> {
        self.apkrs.get_application_backup_agent()
    }

    pub fn get_application_debuggable(&self) -> Option<String> {
        self.apkrs.get_application_debuggable()
    }

    pub fn get_application_description(&self) -> Option<String> {
        self.apkrs.get_application_description()
    }

    pub fn get_application_icon(&self) -> Option<String> {
        self.apkrs.get_application_icon()
    }

    pub fn get_application_logo(&self) -> Option<String> {
        self.apkrs.get_application_logo()
    }

    pub fn get_application_label(&self) -> Option<String> {
        self.apkrs.get_application_label()
    }

    pub fn get_application_name(&self) -> Option<String> {
        self.apkrs.get_application_name()
    }

    pub fn get_permissions(&self) -> HashSet<&str> {
        self.apkrs.get_permissions().collect()
    }

    pub fn get_permissions_sdk23(&self) -> HashSet<&str> {
        self.apkrs.get_permissions_sdk23().collect()
    }

    pub fn get_min_sdk_version(&self) -> Option<String> {
        self.apkrs.get_min_sdk_version()
    }

    pub fn get_target_sdk_version(&self) -> u32 {
        self.apkrs.get_target_sdk_version()
    }

    pub fn get_max_sdk_version(&self) -> Option<String> {
        self.apkrs.get_max_sdk_version()
    }

    pub fn get_libraries(&self) -> HashSet<&str> {
        self.apkrs.get_libraries().collect()
    }

    pub fn get_native_libraries(&self) -> HashSet<&str> {
        self.apkrs.get_native_libraries().collect()
    }

    pub fn get_features(&self) -> HashSet<&str> {
        self.apkrs.get_features().collect()
    }

    pub fn is_automotive(&self) -> bool {
        self.apkrs.is_automotive()
    }

    pub fn is_leanback(&self) -> bool {
        self.apkrs.is_leanback()
    }

    pub fn is_wearable(&self) -> bool {
        self.apkrs.is_wearable()
    }

    pub fn is_chromebook(&self) -> bool {
        self.apkrs.is_chromebook()
    }

    pub fn get_declared_permissions(&self) -> HashSet<Permission> {
        self.apkrs
            .get_declared_permissions()
            .map(Permission::from)
            .collect()
    }

    pub fn get_main_activity(&self) -> Option<&str> {
        self.apkrs.get_main_activity()
    }

    // Use a vector instead of a hashset to preserve the order of the found activities
    pub fn get_main_activities(&self) -> Vec<&str> {
        self.apkrs.get_main_activities().collect()
    }

    pub fn get_activities(&self) -> Vec<Activity> {
        self.apkrs.get_activities().map(Activity::from).collect()
    }

    pub fn get_services(&self) -> Vec<Service> {
        self.apkrs.get_services().map(Service::from).collect()
    }

    pub fn get_receivers(&self) -> Vec<Receiver> {
        self.apkrs.get_receivers().map(Receiver::from).collect()
    }

    pub fn get_providers(&self) -> Vec<Provider> {
        self.apkrs.get_providers().map(Provider::from).collect()
    }

    pub fn get_signatures<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, Signature>>> {
        Ok(self
            .apkrs
            .get_signatures()
            .map_err(|e| APKError::new_err(format!("failed to get signatures: {:?}", e)))?
            .into_iter()
            .filter_map(|x| Signature::from(py, x))
            .collect())
    }
}

#[pymodule]
fn apk_info(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    env_logger::init();

    m.add("APKError", m.py().get_type::<APKError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<CertificateInfo>()?;
    m.add_class::<Activity>()?;
    m.add_class::<Permission>()?;
    m.add_class::<Provider>()?;
    m.add_class::<Receiver>()?;
    m.add_class::<Service>()?;
    m.add_class::<Signature>()?;

    m.add_class::<Apk>()?;
    Ok(())
}
