//! The C boundary.
//!
//! Directions are fixed: `libfprint` calls the exported entry point, the shim's GObject code runs
//! in C, and later tickets make the shim's vfuncs call back into Rust functions that own the
//! protocol core. No protocol type crosses this seam; what crosses is a `GType`, and later the
//! opaque pointer to a core object and the actions the core returns.

/// glib's `GType`: an opaque, non-zero integer naming a registered GObject type.
///
/// `gsize` is `usize`, and glib guarantees a `GType` is never zero, but the value is only ever
/// produced and consumed by C here, so it stays opaque.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GType(usize);

// SAFETY: the declaration matches the C definition in `shim/cv3_tod.c`, which `build.rs`
// compiles from the same crate. Both return glib's `GType`, an unsigned integer of pointer size.
unsafe extern "C" {
    /// Registers the plugin's `FpDevice` subclass on first call and returns its `GType`.
    pub safe fn cv3_tod_shim_get_type() -> GType;
}

/// The symbol `libfprint`'s TOD loader resolves in the plugin.
///
/// The body is the C shim's, but the symbol is exported from Rust: rustc gives a `cdylib` a
/// linker version script listing only the symbols the Rust crate declares, so a C-defined entry
/// point would be hidden inside the shared object.
#[unsafe(export_name = "fpi_tod_shared_driver_get_type")]
pub extern "C" fn entry_point() -> GType {
    cv3_tod_shim_get_type()
}
