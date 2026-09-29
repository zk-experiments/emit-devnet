//! The demo as a test, against a spawned node: `cargo test -- --ignored devnet` (needs forge and
//! cast on PATH, and the network the first time: eid's packs and Noir source, the catalogs).
//! Alice (US passport) deposits 100 and pays Bob (DE passport) 60 on the handshake and 5 on the
//! ratchet; Bob's listener sees both with Alice's MRZ; Bob splits, merges and withdraws 30 to
//! his EOA; every balance is checked exactly, the EOA's net of the withdrawal's gas.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RPC_PORT: u16 = 28545;
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const BOB_EOA: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rpc() -> String {
    format!("http://127.0.0.1:{RPC_PORT}")
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn cast(args: &[&str]) -> String {
    run(Command::new("cast").args(args).args(["--rpc-url", &rpc()]))
        .trim()
        .to_string()
}

fn wei(s: &str) -> u128 {
    s.split_whitespace()
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or_else(|_| panic!("wei: {s}"))
}

#[test]
#[ignore = "spawns a node and proves: cargo test -- --ignored devnet"]
fn devnet_end_to_end() {
    let dir = std::env::temp_dir().join(format!("emit-devnet-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("wallets")).expect("dir");
    let zkpool_bin = Path::new(env!("CARGO_BIN_EXE_emit-node")).with_file_name("zkpool");
    assert!(
        zkpool_bin.exists(),
        "{} (built by cargo test over the workspace)",
        zkpool_bin.display()
    );

    let _node = Node(
        Command::new(env!("CARGO_BIN_EXE_emit-node"))
            .args(["node", "--dev", "--chain"])
            .arg(root().join("genesis.json"))
            .arg("--datadir")
            .arg(dir.join("chain"))
            .args([
                "--http",
                "--http.api",
                "eth,net,web3,debug",
                "--ws",
                "--disable-discovery",
                "--ipcdisable",
            ])
            .args([
                "--http.port",
                &RPC_PORT.to_string(),
                "--ws.port",
                &(RPC_PORT + 1).to_string(),
            ])
            .args([
                "--authrpc.port",
                &(RPC_PORT + 6).to_string(),
                "--port",
                &(RPC_PORT + 2000).to_string(),
            ])
            .arg("--log.file.directory")
            .arg(dir.join("logs"))
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("node.log")).expect("log"))
            .spawn()
            .expect("emit-node"),
    );
    let start = Instant::now();
    while Command::new("cast")
        .args(["chain-id", "--rpc-url", &rpc()])
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "node did not start: {}",
            dir.join("node.log").display()
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    let z = |args: &[&str]| -> String {
        run(Command::new(&zkpool_bin)
            .args([
                "--home",
                dir.join("wallets").to_str().expect("utf-8"),
                "--rpc",
                &rpc(),
            ])
            .args(["--ws", &format!("ws://127.0.0.1:{}", RPC_PORT + 1)])
            .args(args)
            .env_remove("ZKPOOL_WALLET"))
    };
    let info = z(&["info"]);
    let field = |k: &str| {
        info.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_else(|| panic!("{k} in {info}"))
            .to_string()
    };
    let deploy = run(Command::new("forge")
        .current_dir(root().join("contracts"))
        .args([
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            &rpc(),
            "--broadcast",
            "--private-key",
            DEPLOYER_KEY,
        ])
        .env("DEPLOYMENT_ROOT", field("deployment_root"))
        .env("PIPELINE_ROOT", field("identity_transfer"))
        .env(
            "REGISTRY_ROOTS",
            format!("{},{}", field("fixtures_registry"), field("csca_registry")),
        ));
    let pool = deploy
        .lines()
        .find_map(|l| l.trim().strip_prefix("EmitV2Pool "))
        .expect("pool address")
        .to_string();
    let zp = |args: &[&str]| z(&[&["--pool", &pool], args].concat());

    zp(&[
        "identity",
        "new",
        "--name",
        "alice",
        "--document",
        "us_rsa4096_rsa2048",
    ]);
    zp(&[
        "identity",
        "new",
        "--name",
        "bob",
        "--document",
        "de_bp384_bp256",
    ]);
    let bundle =
        |n: &str| std::fs::read_to_string(dir.join(format!("wallets/{n}.bundle"))).expect("bundle");
    zp(&[
        "-w",
        "alice",
        "contact",
        "add",
        "--name",
        "bob",
        "--bundle",
        &bundle("bob"),
    ]);
    zp(&[
        "-w",
        "bob",
        "contact",
        "add",
        "--name",
        "alice",
        "--bundle",
        &bundle("alice"),
    ]);

    // Bob listens while Alice pays.
    let listen = Command::new(&zkpool_bin)
        .args([
            "--home",
            dir.join("wallets").to_str().expect("utf-8"),
            "--rpc",
            &rpc(),
            "--pool",
            &pool,
        ])
        .args(["--ws", &format!("ws://127.0.0.1:{}", RPC_PORT + 1)])
        .args(["-w", "bob", "listen", "--until", "2", "--timeout", "900"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("listen");
    std::thread::sleep(Duration::from_secs(2));
    let mut log = vec![];
    log.push(zp(&["-w", "alice", "deposit", "--amount", "100"]));
    log.push(zp(&[
        "-w", "alice", "transfer", "--to", "bob", "--amount", "60",
    ]));
    log.push(zp(&[
        "-w", "alice", "transfer", "--to", "bob", "--amount", "5",
    ]));
    let heard =
        String::from_utf8_lossy(&listen.wait_with_output().expect("listen").stdout).into_owned();
    print!("{heard}");
    assert!(heard.contains("received 60 ETH (handshake"), "{heard}");
    assert!(heard.contains("received 5 ETH (ratchet index 1"), "{heard}");
    assert!(heard.contains("from P<USAERIKSSON<<ANNA<MARIA"), "{heard}");
    assert!(zp(&["-w", "bob", "sync"]).contains("balance 65 ETH"));

    log.push(zp(&["-w", "bob", "split", "--amounts", "10,49.99"]));
    log.push(zp(&["-w", "bob", "merge"]));
    let before = wei(&cast(&["balance", BOB_EOA]));
    let withdraw = zp(&["-w", "bob", "withdraw", "--amount", "30", "--to", BOB_EOA]);
    log.push(withdraw.clone());
    let tx = withdraw
        .split("tx ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("tx");
    let gas = wei(&cast(&["receipt", tx, "gasUsed"]));
    let price = wei(&cast(&["receipt", tx, "effectiveGasPrice"]));
    let after = wei(&cast(&["balance", BOB_EOA]));
    assert_eq!(
        after,
        before + 30 * 10u128.pow(18) - gas * price,
        "Bob's EOA: +30 ETH, less the gas"
    );

    assert!(zp(&["-w", "alice", "balance"]).contains("shielded 34.98 ETH in 1 note(s)"));
    assert!(zp(&["-w", "bob", "balance"]).contains("shielded 34.97 ETH in 2 note(s)"));
    assert_eq!(
        wei(&cast(&["balance", &pool])),
        69_950_000_000_000_000_000,
        "the pool holds the shielded 69.95"
    );
    for l in log.iter().flat_map(|s| s.lines()) {
        println!("{l}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
