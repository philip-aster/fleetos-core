// SPDX-License-Identifier: Apache-2.0
//! CR-17 (CR-CORE-7): canonical service-name → dummy-IP hostname convention.
//!
//! Ruling E chose `/etc/hosts` injection for service-name resolution. This is
//! the single canonical naming scheme that agent, router, and guest-init all
//! call to produce identical `/etc/hosts` lines. Core owns the convention;
//! consumers never re-implement it.
//!
//! Format: `{service}.{role}.{tenant}.svc.{trust_domain}` — all lowercase,
//! DNS-label-safe. Role is always present (the dummy-IP allocator keys on
//! `(service, role)`).

/// Errors from hostname construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NamingError {
    #[error("label is empty")]
    EmptyLabel,
    #[error("label {0:?} is not DNS-label-safe")]
    UnsafeLabel(String),
    #[error("label {0:?} exceeds 63 octets")]
    LabelTooLong(String),
}

/// Build the canonical dummy-IP hostname for a `(service, role, tenant, trust_domain)`.
///
/// All labels are lowercased and validated for DNS-label safety. `trust_domain`
/// is a dotted domain (e.g. `fleet.example.internal`); each of its labels is
/// validated individually. Returns `{service}.{role}.{tenant}.svc.{trust_domain}`.
pub fn dummy_ip_hostname(
    service: &str,
    role: &str,
    tenant: &str,
    trust_domain: &str,
) -> Result<String, NamingError> {
    let service = service.to_ascii_lowercase();
    let role = role.to_ascii_lowercase();
    let tenant = tenant.to_ascii_lowercase();
    let trust_domain = trust_domain.to_ascii_lowercase();

    validate_label(&service)?;
    validate_label(&role)?;
    validate_label(&tenant)?;
    if trust_domain.is_empty() {
        return Err(NamingError::EmptyLabel);
    }
    for part in trust_domain.split('.') {
        validate_label(part)?;
    }

    Ok(format!(
        "{}.{}.{}.svc.{}",
        service, role, tenant, trust_domain
    ))
}

/// A DNS label: 1–63 chars, ASCII alphanumerics and '-', must not start or end
/// with '-'.
fn validate_label(label: &str) -> Result<(), NamingError> {
    if label.is_empty() {
        return Err(NamingError::EmptyLabel);
    }
    if label.len() > 63 {
        return Err(NamingError::LabelTooLong(label.to_owned()));
    }
    let safe = label
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !label.starts_with('-')
        && !label.ends_with('-');
    if !safe {
        return Err(NamingError::UnsafeLabel(label.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form() {
        let h = dummy_ip_hostname("db", "replica", "acme", "fleet.example.internal").unwrap();
        assert_eq!(h, "db.replica.acme.svc.fleet.example.internal");
    }

    #[test]
    fn lowercases_inputs() {
        let h = dummy_ip_hostname("DB", "Replica", "ACME", "Fleet.Example.Internal").unwrap();
        assert_eq!(h, "db.replica.acme.svc.fleet.example.internal");
    }

    #[test]
    fn rejects_unsafe_labels() {
        assert!(dummy_ip_hostname("", "r", "t", "d").is_err());
        assert!(dummy_ip_hostname("db", "r", "t", "d").is_ok());
        assert!(dummy_ip_hostname("db_", "r", "t", "d").is_err()); // '_' not allowed
        assert!(dummy_ip_hostname("-db", "r", "t", "d").is_err());
        assert!(dummy_ip_hostname("db-", "r", "t", "d").is_err());
        assert!(dummy_ip_hostname("db", "r", "t", "fleet..internal").is_err()); // empty label
    }
}
