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
        "usage: cvctl devices\n       cvctl handshake [--show-key] [--hex] [--record <file>]\n       \
         cvctl open [--bad-sequence] [--hex] [--record <file>]\n       \
         cvctl close [--hex] [--record <file>]\n       \
         cvctl capture [--hex]\n       cvctl enroll [--hex]\n       \
         cvctl enroll-then-verify [--hex]\n       cvctl verify [--hex]\n       \
         cvctl cancel-then-verify [--hex]\n       cvctl replay <file>\n"
    );
}

#[test]
fn replay_of_a_missing_file_exits_non_zero_with_a_clear_message() {
    let path = std::env::temp_dir().join(format!(
        "cv3-cli-missing-{}-{}.cvrec",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_file(&path);

    let output = Command::new(env!("CARGO_BIN_EXE_cvctl"))
        .arg("replay")
        .arg(&path)
        .output()
        .expect("cvctl runs");

    assert_ne!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot read transcript"),
        "the message names the missing transcript: {stderr}"
    );
}
