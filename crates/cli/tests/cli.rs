//! The binary's offline surface (and, as an integration test, it makes `cargo test` build the
//! `zkpool` binary the devnet test in crates/node drives).

use std::process::Command;

#[test]
fn info_prints_the_pinned_deployment() {
    let out = Command::new(env!("CARGO_BIN_EXE_zkpool"))
        .arg("info")
        .output()
        .expect("zkpool");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("deployment_root   0x04f372b3"), "{s}");
    assert!(s.contains("fixtures_registry 0x"), "{s}");
}

#[test]
fn a_bad_bundle_is_refused() {
    let home = std::env::temp_dir().join(format!("zkpool-cli-{}", std::process::id()));
    let z = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_zkpool"))
            .args(["--home", home.to_str().expect("utf-8")])
            .args(args)
            .output()
            .expect("zkpool")
    };
    assert!(
        z(&[
            "identity",
            "new",
            "--name",
            "alice",
            "--document",
            "us_rsa4096_rsa2048"
        ])
        .status
        .success()
    );
    let bad = z(&[
        "-w", "alice", "contact", "add", "--name", "x", "--bundle", "AAAA",
    ]);
    assert!(!bad.status.success());
    let bob = z(&[
        "identity",
        "new",
        "--name",
        "bob",
        "--document",
        "de_bp384_bp256",
    ]);
    assert!(bob.status.success());
    let bundle = std::fs::read_to_string(home.join("bob.bundle")).expect("bundle");
    let wrong_chain = z(&[
        "-w",
        "alice",
        "--chain-id",
        "1",
        "contact",
        "add",
        "--name",
        "bob",
        "--bundle",
        &bundle,
    ]);
    assert!(String::from_utf8_lossy(&wrong_chain.stderr).contains("WrongChain"));
    assert!(
        z(&[
            "-w", "alice", "contact", "add", "--name", "bob", "--bundle", &bundle
        ])
        .status
        .success()
    );
    let _ = std::fs::remove_dir_all(home);
}
