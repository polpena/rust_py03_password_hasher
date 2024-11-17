use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use pyo3::prelude::*;

/// Hashes a password using Argon2 and returns the hashed password as a string.
///
/// # Arguments
///
/// * `password` - The plaintext password to hash.
///
/// # Returns
///
/// A `PyResult` containing the hashed password string or an error.
#[pyfunction]
fn hash_password(password: &str) -> PyResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?
        .to_string();
    Ok(password_hash)
}

/// Verifies a plaintext password against a hashed password.
///
/// # Arguments
///
/// * `password` - The plaintext password to verify.
/// * `password_hash` - The hashed password to verify against.
///
/// # Returns
///
/// A `PyResult` containing `true` if the password is valid, or `false` otherwise.
#[pyfunction]
fn verify_password(password: &str, password_hash: &str) -> PyResult<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let is_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    Ok(is_valid)
}

#[pymodule]
fn password_hasher(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    Ok(())
}
