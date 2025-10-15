use pyo3::prelude::*;

#[pymodule]
fn _apk(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
