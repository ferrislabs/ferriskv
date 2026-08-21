//! Node configuration parsing, from raw TOML through to validation.
//!
//! Operators hand this file to the node, and a panic here is a node that cannot
//! start and cannot say why. Reaching `validate` matters as much as parsing: a
//! config that deserializes but describes an impossible node must be rejected
//! with a message, not with an arithmetic overflow later on.

#![no_main]

use config::{Config, File, FileFormat};
use ferriskv_node::NodeConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(built) = Config::builder()
        .add_source(File::from_str(text, FileFormat::Toml))
        .build()
    else {
        return;
    };

    let Ok(cfg) = built.try_deserialize::<NodeConfig>() else {
        return;
    };

    // Validation is where a parsed-but-nonsensical config is supposed to be
    // caught, so it is part of what this target covers.
    if cfg.validate().is_ok() {
        assert!(!cfg.node_id.is_empty());
        assert!(cfg.shutdown_timeout_secs > 0);
        assert!(cfg.wal_rotate_bytes >= 4096);
    }
});
