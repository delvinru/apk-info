use std::collections::HashSet;
use std::path::PathBuf;

use ::apk_info::apk::Apk as ApkRust;
use ::apk_info::models::{Receiver as ApkReceiver, Service as ApkService};
use ::apk_info_zip::{CertificateInfo as ZipCertificateInfo, Signature as ZipSignature};
use pyo3::exceptions::{PyException, PyFileNotFoundError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyString;
use pyo3::{Bound, PyAny, PyResult, create_exception, pyclass, pymethods};

create_exception!(m, APKError, PyException, "Got error while parsing apk");

#[pyclass(eq, frozen)]
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

#[pyclass(eq, frozen)]
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

#[pyclass(frozen)]
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
    isolated_process: Option<String>,

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
            isolated_process: service.isolated_process.map(String::from),
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

#[pyclass(frozen)]
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

#[pyclass(name = "APK", unsendable)]
struct Apk {
    /// Store rust object in memory
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

    /// Read data from zip by filename
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

    /// List of the filenames included in the central directory
    pub fn get_files(&self) -> Vec<&str> {
        self.apkrs.get_files().collect()
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

    pub fn get_target_sdk_version(&self) -> Option<String> {
        self.apkrs.get_target_sdk_version()
    }

    pub fn get_max_sdk_version(&self) -> Option<String> {
        self.apkrs.get_max_sdk_version()
    }

    pub fn get_libraries(&self) -> HashSet<&str> {
        self.apkrs.get_libraries().collect()
    }

    pub fn get_features(&self) -> HashSet<&str> {
        self.apkrs.get_features().collect()
    }

    pub fn get_declared_permissions(&self) -> HashSet<&str> {
        self.apkrs.get_declared_permissions().collect()
    }

    // Use a vector instead of a hashset to preserve the order of the found activities
    pub fn get_main_activities(&self) -> Vec<&str> {
        self.apkrs.get_main_activities().collect()
    }

    pub fn get_activities(&self) -> HashSet<&str> {
        self.apkrs.get_activities().collect()
    }

    pub fn get_services(&self) -> HashSet<Service> {
        self.apkrs.get_services().map(Service::from).collect()
    }

    pub fn get_receivers(&self) -> HashSet<Receiver> {
        self.apkrs.get_receivers().map(Receiver::from).collect()
    }

    pub fn get_providers(&self) -> HashSet<&str> {
        self.apkrs.get_providers().collect()
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
    m.add_class::<Signature>()?;
    m.add_class::<Service>()?;
    m.add_class::<Receiver>()?;

    m.add_class::<Apk>()?;
    Ok(())
}
