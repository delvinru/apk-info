//! Python class for the structural anomalies of an apk.

use std::fmt;

use ::apk_info::Anomaly as ApkAnomaly;
use pyo3::prelude::*;

/// A structural defect of an apk.
#[pyclass(eq, frozen, module = "apk_info._apk_info")]
#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct Anomaly {
    #[pyo3(get)]
    code: &'static str,
    #[pyo3(get)]
    severity: &'static str,
    #[pyo3(get)]
    location: Option<String>,
    #[pyo3(get)]
    detail: String,
}

impl From<ApkAnomaly> for Anomaly {
    fn from(anomaly: ApkAnomaly) -> Self {
        Self {
            code: anomaly.code(),
            severity: anomaly.severity.as_str(),
            detail: anomaly.to_string(),
            location: anomaly.location,
        }
    }
}

impl fmt::Debug for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = match &self.location {
            Some(location) => format!("'{location}'"),
            None => "None".to_owned(),
        };
        write!(
            f,
            "Anomaly(code='{}', severity='{}', location={location}, detail='{}')",
            self.code, self.severity, self.detail
        )
    }
}

#[pymethods]
impl Anomaly {
    fn __repr__(&self) -> String {
        format!("{self:?}")
    }
}
