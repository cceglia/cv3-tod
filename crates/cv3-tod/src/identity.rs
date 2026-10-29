//! The plugin's identity as `libfprint` sees it.
//!
//! The class id and full name are defined once, in `build.rs`: it writes `cv3_tod_identity.h` for
//! the C shim and passes the same values here with `cargo:rustc-env`, so neither side holds a copy
//! that can drift. The USB ids are the core's, not copies, so the plugin and the probe cannot
//! disagree about which sensor they claim.

use cv3_core::proto;

/// The driver id, reported by `libfprint` as the device's `driver`.
pub const CLASS_ID: &str = env!("CV3_TOD_CLASS_ID");

/// The human readable name shown for the device.
pub const FULL_NAME: &str = env!("CV3_TOD_FULL_NAME");

/// The symbol `libfprint`'s TOD loader resolves in every plugin shared object.
pub const ENTRY_POINT: &str = "fpi_tod_shared_driver_get_type";

/// Vendor of the only sensor this plugin claims.
pub const VENDOR_ID: u16 = proto::VENDOR_ID;

/// Product of the only sensor this plugin claims.
pub const PRODUCT_ID: u16 = proto::PRODUCT_ID;
