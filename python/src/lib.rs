//! Python bindings for apk-info, built as the `apk_info` module.
//!
//! - [`apk`]: the `APK` class over [`apk_info::Apk`];
//! - [`anomaly`]: structural anomalies of an apk;
//! - [`components`]: activities, services and other manifest elements;
//! - [`signature`]: signatures and certificates.

#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod anomaly;
mod apk;
mod components;
mod signature;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(
    apk_info,
    APKError,
    PyException,
    "Got error while parsing apk"
);

#[pymodule]
fn apk_info(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // another extension may have set the global logger already: keep it,
    // a panic here would fail the import
    let _ = env_logger::try_init();

    m.add("APKError", m.py().get_type::<APKError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_class::<apk::Apk>()?;
    m.add_class::<anomaly::Anomaly>()?;
    m.add_class::<signature::CertificateInfo>()?;
    m.add_class::<signature::Signature>()?;
    m.add_class::<components::IntentFilter>()?;
    m.add_class::<components::Activity>()?;
    m.add_class::<components::ActivityAlias>()?;
    m.add_class::<components::Permission>()?;
    m.add_class::<components::Provider>()?;
    m.add_class::<components::Service>()?;
    m.add_class::<components::Receiver>()?;
    m.add_class::<components::Attribution>()?;
    Ok(())
}
