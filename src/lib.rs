use anyhow::{format_err, Ok, Result};
use base64::prelude::*;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

/// Verify `password` based on `encoded_password` which is managed by Django,
/// return Ok(true) if verification is successful, otherwise return false.
///
/// Currently only the default pbkdf2_sha256 algorithm is supported.
/// # Usage
///
/// ```rust
/// use django_auth::*;
///
/// let res = django_auth(
///     "hello",
///     "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU=",
/// ).expect("django_auth error");
///
/// assert!(res);
/// ```
pub fn django_auth(password: &str, encoded_password: &str) -> Result<bool> {
    // split hashed_password into 4 parts: algorithm, iterations, salt, hash
    let parts = encoded_password.split('$');

    let parts: Vec<&str> = parts.take(4).collect();
    if parts.len() != 4 {
        return Err(format_err!("invalid django hashed password"));
    }

    let (algorithm, iterations, salt) = (parts[0], parts[1], parts[2]);

    if algorithm != "pbkdf2_sha256" {
        return Err(format_err!("algorithm {algorithm} is not supported"));
    }

    let iterations: u32 = iterations
        .parse()
        .expect("invalid iterations in hashed password");

    let encoded = django_encode_password(password, salt, iterations)?;
    Ok(encoded == encoded_password)
}

/// Encode `password` in Django way.
///
/// # Usage
///
/// ```rust
/// use django_auth::*;
/// let password = "hello";
/// let encoded_password = django_encode_password(password, "btQDcwXF2RoK6Q", 0)
///     .expect("django_encode_password error");

/// assert_eq!(
///     encoded_password,
///     "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU="
/// );

/// django_auth(password, &encoded_password).expect("auth failed");
///
pub fn django_encode_password(password: &str, salt: &str, mut iterations: u32) -> Result<String> {
    if salt.contains('$') {
        return Err(format_err!("salt contains dollar sign ($)"));
    }

    if iterations == 0 {
        iterations = 180000;
    }

    let hash = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt.as_bytes(), iterations);
    let hash = BASE64_STANDARD.encode(hash);
    let res = format!("{}${}${}${}", "pbkdf2_sha256", iterations, salt, hash);

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_django_auth() {
        let res = django_auth(
            "hello",
            "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU=",
        )
        .unwrap();

        assert!(res);

        let res = django_auth(
            "hello",
            "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU",
        )
        .unwrap();
        assert!(!res);

        let res = django_auth("world", "abc$edf");
        assert!(res.is_err());
    }

    #[test]
    fn test_djaongo_encode_password() {
        let password = "hello";
        let encoded_password = django_encode_password(password, "btQDcwXF2RoK6Q", 0)
            .expect("django_encode_password failed");
        assert_eq!(
            encoded_password,
            "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU="
        );
        django_auth(password, &encoded_password).expect("auth failed");

        let password = "hello";
        let res = django_encode_password(password, "btQDcwXF$2RoK6Q", 0);
        assert!(res.is_err());

        let password = "hello";
        let encoded_password = django_encode_password(password, "btQDcwXF2RoK6Q", 10)
            .expect("django_encode_password failed");
        assert_ne!(
            encoded_password,
            "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU="
        );

        let password = "hello";
        let encoded_password = django_encode_password(password, "btQDcwXF2RoK6Qx", 0)
            .expect("django_encode_password failed");
        assert_ne!(
            encoded_password,
            "pbkdf2_sha256$180000$btQDcwXF2RoK6Q$D4cC7bgbaIZGHsTdw9TYhRfuLfLGbsZlI4Rp802e7kU="
        );
    }
}
