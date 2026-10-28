//! The process-level seam: what `cvctl` actually exits with is part of its contract.

use std::process::Command;

#[test]
fn a_bare_invocation_prints_usage_to_stderr_and_exits_one() {
    let output = Command::new(env!("CARGO_BIN_EXE_cvctl"))
        .output()
        .expect("cvctl runs");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "usage: cvctl devices\n       cvctl handshake [--show-key]\n       cvctl open \
         [--bad-sequence]\n       cvctl close\n"
    );
}
