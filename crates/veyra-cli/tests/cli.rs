//! Black-box CLI behavior over the real embedded local API.

use predicates::prelude::*;

#[test]
fn demo_exercises_commit_audit_and_rollback_without_credentials() {
    assert_cmd::cargo::cargo_bin_cmd!("veyra")
        .args(["demo", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"committed\":true"))
        .stdout(predicate::str::contains("\"audit_valid\":true"))
        .stdout(predicate::str::contains(
            "\"rollback_state\":\"rolled_back\"",
        ))
        .stdout(predicate::str::contains("\"workspace_file_removed\":true"));
}

#[test]
fn malformed_command_has_a_nonzero_exit_code() {
    assert_cmd::cargo::cargo_bin_cmd!("veyra")
        .arg("not-a-command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}
