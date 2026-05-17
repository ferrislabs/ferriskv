use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "default_max_key_size")]
    pub max_key_size: usize,
    #[serde(default = "default_max_value_size")]
    pub max_value_size: usize,
    #[serde(default = "default_max_batch_ops")]
    pub max_batch_ops: usize,
    #[serde(default = "default_max_scan_limit")]
    pub max_scan_limit: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_key_size: default_max_key_size(),
            max_value_size: default_max_value_size(),
            max_batch_ops: default_max_batch_ops(),
            max_scan_limit: default_max_scan_limit(),
        }
    }
}

const fn default_max_key_size() -> usize {
    4 * 1024
}
const fn default_max_value_size() -> usize {
    10 * 1024 * 1024
}
const fn default_max_batch_ops() -> usize {
    1000
}
const fn default_max_scan_limit() -> u32 {
    10_000
}

impl Limits {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_key_size == 0 {
            return Err("limits.max_key_size must be > 0".into());
        }
        if self.max_value_size == 0 {
            return Err("limits.max_value_size must be > 0".into());
        }
        if self.max_batch_ops == 0 {
            return Err("limits.max_batch_ops must be > 0".into());
        }
        if self.max_scan_limit == 0 {
            return Err("limits.max_scan_limit must be > 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let l = Limits::default();
        assert_eq!(l.max_key_size, 4 * 1024);
        assert_eq!(l.max_value_size, 10 * 1024 * 1024);
        assert_eq!(l.max_batch_ops, 1000);
        assert_eq!(l.max_scan_limit, 10_000);
        assert!(l.validate().is_ok());
    }

    #[test]
    fn zero_fields_are_rejected() {
        let l = Limits {
            max_key_size: 0,
            ..Limits::default()
        };
        assert!(l.validate().is_err());

        let l = Limits {
            max_batch_ops: 0,
            ..Limits::default()
        };
        assert!(l.validate().is_err());
    }
}
