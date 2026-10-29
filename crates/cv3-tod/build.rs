//! Compiles the C shim against the distribution's libfprint TOD headers and links it into the
//! plugin.
//!
//! The shim needs `libfprint-2-tod-1` both for its headers and, at link time, for its versioned
//! symbols: glibc resolves an unversioned undefined reference to the *base* version of a symbol,
//! and `fpi_ssm_new_full` has a legacy 4-argument definition at `LIBFPRINT_TOD_1.0.0` and the
//! modern one at `LIBFPRINT_TOD_1_1.92`. `scripts/check-tod-link.sh` inspects the built object and
//! fails on the legacy binding; this script only has to make sure the library really is linked.
//!
//! The C object is linked by path rather than as a `cc` archive: rustc gives a `cdylib` a linker
//! version script that exports only the symbols the Rust crate declares, so symbols pulled in from
//! a static archive are local. The object's GType entry point is called from `src/ffi.rs`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The TOD package: headers, and the versioned symbols the shim must bind to.
const TOD_PACKAGE: &str = "libfprint-2-tod-1";
/// GLib's object system, which the shim calls directly through the generated type code.
const GLIB_PACKAGES: [&str; 2] = ["gobject-2.0", "glib-2.0"];

fn main() {
    println!("cargo:rerun-if-changed=shim/cv3_tod.c");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));

    let packages = [TOD_PACKAGE, GLIB_PACKAGES[0], GLIB_PACKAGES[1]];
    let cflags = pkg_config("--cflags", &packages);
    let libs = pkg_config("--libs", &packages);

    let object = compile_shim(&manifest_dir, &out_dir, &cflags);

    // Everything the shim calls goes through these libraries, and the object must come first so
    // that `--as-needed` (Ubuntu's default) does not discard a library before it is referenced.
    println!("cargo:rustc-link-arg-cdylib=-Wl,--no-as-needed");
    println!("cargo:rustc-link-arg-cdylib={}", object.display());
    for arg in split_flags(&libs) {
        println!("cargo:rustc-link-arg-cdylib={arg}");
    }
}

/// Compiles `shim/cv3_tod.c` to an object file and returns its path.
fn compile_shim(manifest_dir: &Path, out_dir: &Path, cflags: &str) -> PathBuf {
    let source = manifest_dir.join("shim/cv3_tod.c");
    let object = out_dir.join("cv3_tod_shim.o");

    let mut build = cc::Build::new();
    build
        .file(&source)
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .flag_if_supported("-std=gnu11")
        .flag("-fPIC");
    for flag in split_flags(cflags) {
        build.flag(flag);
    }

    let mut command = build.get_compiler().to_command();
    command
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .current_dir(manifest_dir);

    run(&mut command, "compile shim/cv3_tod.c");
    object
}

/// Runs `pkg-config` with `args` and returns its stdout, failing the build with an actionable
/// message when the TOD headers or library are missing.
fn pkg_config(args: &str, packages: &[&str]) -> String {
    let mut command = Command::new("pkg-config");
    command.arg(args).args(packages);

    let output = command.output().unwrap_or_else(|error| {
        panic!("could not run pkg-config ({error}); install pkg-config and libfprint-2-tod-dev")
    });
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "pkg-config {args} {} failed: {}\n\
             the TOD plugin needs the distribution's libfprint TOD headers:\n\
             \x20   sudo apt install libfprint-2-tod-dev pkg-config",
            packages.join(" "),
            stderr.trim()
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Splits a `pkg-config` flag string. The flags never contain spaces inside a value.
fn split_flags(flags: &str) -> impl Iterator<Item = &str> {
    flags.split_whitespace()
}

/// Runs a compiler command, failing the build loudly when it cannot start or exits non-zero.
fn run(command: &mut Command, what: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("could not {what}: {error}; install a C compiler"));
    assert!(
        status.success(),
        "{what} failed: {status}; the TOD plugin needs libfprint-2-tod-dev and a C toolchain"
    );
}
