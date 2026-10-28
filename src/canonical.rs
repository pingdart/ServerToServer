use anyhow::{bail, Result};

/// Normalizes and validates an incoming domain string.
/// Strips protocol prefixes (http://, https://, sds://), trailing slashes,
/// path components, port numbers, and converts to lowercase ASCII.
pub fn normalize_domain(input: &str) -> Result<String> {
    let mut s = input.trim();

    // Strip scheme
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    }

    // Strip path or query
    if let Some(pos) = s.find('/') {
        s = &s[..pos];
    }

    // Strip port
    if let Some(pos) = s.find(':') {
        s = &s[..pos];
    }

    let mut domain = s.trim().to_lowercase();

    // Strip trailing root dot
    if domain.ends_with('.') {
        domain.pop();
    }

    if domain.is_empty() {
        bail!("Domain cannot be empty");
    }

    // Basic FQDN validation
    if !domain.contains('.') {
        bail!(
            "Invalid domain '{}': Missing top-level domain extension",
            domain
        );
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("Invalid label '{}' in domain '{}'", label, domain);
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!(
                "Domain label cannot start or end with a hyphen: '{}'",
                label
            );
        }
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                bail!("Invalid character '{}' in domain label '{}'", c, label);
            }
        }
    }

    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalization() {
        assert_eq!(
            normalize_domain("https://meddylist.com/").unwrap(),
            "meddylist.com"
        );
        assert_eq!(
            normalize_domain("MEDDYLIST.COM:8080").unwrap(),
            "meddylist.com"
        );
        assert_eq!(normalize_domain("sds://xyz.com.").unwrap(), "xyz.com");
        assert!(normalize_domain("invalid_domain").is_err());
    }
}
