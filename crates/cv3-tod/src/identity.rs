//! The plugin's identity as `libfprint` sees it, for the Rust side of the shim.
//!
//! `shim/cv3_tod.c` is where the device class is described to GObject; these constants name the
//! same facts for the Rust side, and the tests at the crate root keep the two in step. The USB
//! ids are the core's, not copies, so the plugin and the probe cannot disagree about which sensor
//! they claim.

use cv3_core::proto;

/// The driver id, reported by `libfprint` as the device's `driver`.
pub const CLASS_ID: &str = "cv3";

/// The human readable name shown for the device.
pub const FULL_NAME: &str = "Dell/Broadcom ControlVault 3 fingerprint";

/// The symbol `libfprint`'s TOD loader resolves in every plugin shared object.
pub const ENTRY_POINT: &str = "fpi_tod_shared_driver_get_type";

/// Vendor of the only sensor this plugin claims.
pub const VENDOR_ID: u16 = proto::VENDOR_ID;

/// Product of the only sensor this plugin claims.
pub const PRODUCT_ID: u16 = proto::PRODUCT_ID;
