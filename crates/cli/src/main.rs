//! `zkpool`: the devnet's console wallet. See README.md for the flow.

mod chain;
mod document;
mod emit;
mod identity;
mod mailbox;
mod tree;
mod wallet;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use clap::{Parser, Subcommand};
use emit_circuits::setup::Pool;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use wallet::{Plan, Wallet};
use zk_encryption_circuits::wallet::poseidon::FieldHex;
use zk_encryption_circuits::wallet::sender::Sender;

/// The devnet's deployer: the standard test mnemonic's account 0 (genesis.json funds it).
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The devnet's known dev keys (the standard test mnemonic's accounts 1 and 2): Alice's and Bob's
/// funded EOAs (genesis.json). Account 0 deploys.
const DEV_KEYS: [(&str, &str); 2] = [
    (
        "alice",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    ),
    (
        "bob",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    ),
];

#[derive(Parser)]
#[command(name = "zkpool", about = "Console wallet for the Emit V2 devnet")]
struct Cli {
    /// Where wallets are kept (`<name>.json`).
    #[arg(long, env = "ZKPOOL_HOME", global = true)]
    home: Option<PathBuf>,
    #[arg(
        long,
        env = "ZKPOOL_RPC",
        default_value = "http://127.0.0.1:8545",
        global = true
    )]
    rpc: String,
    #[arg(
        long,
        env = "ZKPOOL_WS",
        default_value = "ws://127.0.0.1:8546",
        global = true
    )]
    ws: String,
    /// The EmitV2Pool contract.
    #[arg(long, env = "ZKPOOL_POOL", global = true)]
    pool: Option<Address>,
    /// The wallet to act as.
    #[arg(long, short, env = "ZKPOOL_WALLET", global = true)]
    wallet: Option<String>,
    #[arg(long, env = "ZKPOOL_CHAIN_ID", default_value_t = 3607, global = true)]
    chain_id: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The pinned deployment, the registry roots the pool must accept, and the pin check.
    Info {
        /// Also fetch and check the remote pins (catalogs, registry).
        #[arg(long)]
        check: bool,
    },
    /// Deploys the pool (emit-protocol-abi's bytecode) for the pinned deployment, accepting the
    /// fixtures' CSCA registry root and the published one; prints `EmitV2Pool <address>`.
    Deploy {
        /// The deployer's key (default: the devnet's account 0).
        #[arg(long, env = "ZKPOOL_DEPLOYER_KEY", default_value = DEPLOYER_KEY)]
        key: String,
        /// How long an escrowed note waits for its owner, in seconds.
        #[arg(long, default_value_t = 86_400)]
        escrow_window: u64,
    },
    #[command(subcommand)]
    Identity(IdentityCmd),
    #[command(subcommand)]
    Contact(ContactCmd),
    /// Moves `amount` ETH from the EOA into a new note.
    Deposit {
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "0")]
        fee: String,
    },
    /// Pays a contact privately: the first transfer is the channel's handshake, later ones ratchet.
    Transfer {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "0.01")]
        fee: String,
    },
    /// Moves `amount` ETH out of the pool to an address.
    Withdraw {
        #[arg(long)]
        amount: String,
        #[arg(long)]
        to: Address,
        #[arg(long, default_value = "0.01")]
        fee: String,
    },
    /// Lists the wallet's notes.
    Notes,
    /// Merges the two smallest notes into one (a self-transfer 2 -> 1).
    Merge {
        #[arg(long, default_value = "0.01")]
        fee: String,
    },
    /// Splits one note into two (a self-transfer 1 -> 2): `a,b` needs a note worth exactly
    /// a + b + fee; `a` alone keeps the rest in the second note.
    Split {
        #[arg(long, value_delimiter = ',')]
        amounts: Vec<String>,
        #[arg(long, default_value = "0.01")]
        fee: String,
    },
    /// Lists the escrows addressed here (awaiting this wallet's resolve) and those it sent.
    Escrows,
    /// Resolves escrows addressed here: accepts (the note, less the fee, becomes this wallet's) or
    /// rejects (it goes back to the sender). An escrow is named by a prefix of its C0.
    Resolve {
        /// The escrow's C0 (a prefix is enough); --all for every escrow addressed here.
        #[arg(long, required_unless_present = "all")]
        escrow: Option<String>,
        #[arg(long)]
        all: bool,
        /// Hand it back to the sender instead.
        #[arg(long)]
        reject: bool,
        /// Paid from the note on an accept (a reject pays none).
        #[arg(long, default_value = "0")]
        fee: String,
    },
    /// Hands back an escrow this wallet sent whose window passed (its refund note returns here).
    Refund {
        #[arg(long)]
        escrow: String,
    },
    /// Follows the pool live (a log subscription), printing notes received into escrow.
    Listen {
        /// Stop after this many seconds (default: until Ctrl-C).
        #[arg(long)]
        timeout: Option<u64>,
        /// Stop after receiving this many notes.
        #[arg(long)]
        until: Option<usize>,
    },
    /// Catches up with the pool's logs.
    Sync,
    /// Shielded balance and the EOA's.
    Balance,
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Binds a synthetic passport, generates the shielded and receiver keys, prints the bundle.
    New {
        #[arg(long)]
        name: String,
        /// A fixture: us_rsa4096_rsa2048, de_bp384_bp256, fr_rsa4096_rsa2048, it_pss4096_rsa2048,
        /// nl_rsa3072_rsa2048, es_p521_p256.
        #[arg(long)]
        document: String,
        /// The EOA's private key (default: the dev key of alice or bob).
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// Prints the receiver bundle (base64url).
    Show,
    /// Proves the passport once and registers the shielded key in the pool's identity cache:
    /// every transaction proves membership (member_transfer) until the registration expires. In
    /// an epoch's last day it registers for the next epoch.
    Register {
        /// Register again even if that wouldn't outlast the live registration.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ContactCmd {
    /// Accepts someone's receiver bundle (chain, validity, keys checked).
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        bundle: String,
    },
}

/// What the commands share: where things are, and the registry and the proving pool, loaded once.
pub struct Ctx {
    pub home: PathBuf,
    pub rpc: String,
    pub pool: Option<Address>,
    registry: OnceLock<csca_registry::output::Registry>,
    artifacts: OnceLock<Pool>,
}

impl Ctx {
    pub fn pool_address(&self) -> eyre::Result<Address> {
        self.pool
            .ok_or_else(|| eyre::eyre!("no pool address (--pool or ZKPOOL_POOL)"))
    }

    pub fn registry(&self) -> eyre::Result<&csca_registry::output::Registry> {
        if self.registry.get().is_none() {
            let _ = self.registry.set(document::registry()?);
        }
        Ok(self.registry.get().expect("set"))
    }

    /// The proving pool for these eid circuits: the pins checked (catalogs fetched), then eid's
    /// packs downloaded if not cached.
    pub fn pool(&self, labels: &[String]) -> eyre::Result<&Pool> {
        if self.artifacts.get().is_none() {
            let pins = emit_circuits::pins::Pins::embedded();
            let checks = pins.check(false).map_err(|e| eyre::eyre!(e))?;
            eprintln!("pins: {} checks ok", checks.len());
            let labels: BTreeSet<String> = labels.iter().cloned().collect();
            let pool = emit_circuits::setup::pool(&pins, &labels, &|l| eprintln!("setup: {l}"))
                .map_err(|e| eyre::eyre!("{e}"))?;
            let _ = self.artifacts.set(pool);
        }
        Ok(self.artifacts.get().expect("set"))
    }
}

/// Wei as ETH.
pub fn eth(wei: u128) -> String {
    let s = alloy::primitives::utils::format_ether(U256::from(wei));
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn wei(s: &str) -> eyre::Result<u128> {
    let v = alloy::primitives::utils::parse_ether(s)?;
    u128::try_from(v).map_err(|_| eyre::eyre!("{s}: too large"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn report(what: &str, r: &wallet::Receipt) {
    println!(
        "{what}: {} proved in {:.2} s ({} B proof, verified locally in {:.0} ms), gas {} ({} B calldata), block {}, tx {}",
        r.pipeline, r.prove_s, r.proof_bytes, r.verify_ms, r.gas_used, r.calldata, r.block, r.tx
    );
}

/// A transaction's receipt, then its own escrow's resolve, if any.
fn report_all(name: &str, what: &str, rs: &[wallet::Receipt]) {
    for (i, r) in rs.iter().enumerate() {
        if i == 0 {
            report(what, r);
        } else {
            report(&format!("{name}: accept own escrow"), r);
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let home = cli.home.clone().unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".zkpool")
    });
    let ctx = Ctx {
        home: home.clone(),
        rpc: cli.rpc.clone(),
        pool: cli.pool,
        registry: OnceLock::new(),
        artifacts: OnceLock::new(),
    };
    let name = || {
        cli.wallet
            .clone()
            .ok_or_else(|| eyre::eyre!("which wallet? (--wallet or ZKPOOL_WALLET)"))
    };
    let provider =
        || async { Ok::<_, eyre::Report>(ProviderBuilder::new().connect(&cli.rpc).await?) };

    match cli.cmd {
        Cmd::Deploy { key, escrow_window } => {
            use alloy::primitives::B256;
            use emit_circuits::circuits::{DEPLOYMENT_ROOT, pipelines};
            let pins = emit_circuits::pins::Pins::embedded();
            for line in pins.check(true).map_err(|e| eyre::eyre!(e))? {
                println!("pins: {line}");
            }
            let signer: alloy::signers::local::PrivateKeySigner = key.parse()?;
            let p = ProviderBuilder::new()
                .wallet(signer)
                .connect(&cli.rpc)
                .await?;
            let pool = chain::EmitV2Pool::deploy(
                &p,
                B256::from(DEPLOYMENT_ROOT),
                B256::from(pipelines::identity_register::ROOT),
                B256::from(pipelines::member_transfer::ROOT),
                B256::from(pipelines::member_resolve::ROOT),
                U256::from(escrow_window),
            )
            .await
            .map_err(|e| eyre::eyre!("deploy: {e}"))?;
            let fixtures = U256::from_be_bytes(document::registry_root(ctx.registry()?).to_be32());
            let published = U256::from_str_radix(pins.csca.root.trim_start_matches("0x"), 16)?;
            for root in [fixtures, published] {
                pool.addRegistryRoot(root)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;
            }
            println!("EmitV2Pool {}", pool.address());
        }
        Cmd::Info { check } => {
            use emit_circuits::circuits::{DEPLOYMENT_ROOT, pipelines};
            let pins = emit_circuits::pins::Pins::embedded();
            let reg = ctx.registry()?;
            println!(
                "deployment_root   {}",
                emit_circuits::hex32(&DEPLOYMENT_ROOT)
            );
            println!(
                "identity_register {}",
                emit_circuits::hex32(&pipelines::identity_register::ROOT)
            );
            println!(
                "member_transfer   {}",
                emit_circuits::hex32(&pipelines::member_transfer::ROOT)
            );
            println!(
                "member_resolve    {}",
                emit_circuits::hex32(&pipelines::member_resolve::ROOT)
            );
            println!("fixtures_registry {}", document::registry_root(reg).hex());
            println!("csca_registry     {} ({})", pins.csca.root, pins.csca.tag);
            for line in pins.check(!check).map_err(|e| eyre::eyre!(e))? {
                println!("pins: {line}");
            }
        }
        Cmd::Identity(IdentityCmd::New {
            name,
            document,
            key,
            force,
        }) => {
            if wallet::path(&home, &name).exists() && !force {
                eyre::bail!("wallet {name} exists (--force to replace it)");
            }
            let key = match key {
                Some(k) => k,
                None => DEV_KEYS
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, k)| k.to_string())
                    .ok_or_else(|| eyre::eyre!("--key: only alice and bob have dev keys"))?,
            };
            let w = Wallet::create(&name, &document, key, cli.chain_id)?;
            let signer: alloy::signers::local::PrivateKeySigner = w.key.parse()?;
            w.save(&home)?;
            std::fs::write(home.join(format!("{name}.bundle")), &w.bundle)?;
            let doc = document::by_name(&document)?;
            println!(
                "identity {name}: passport {document} ({})",
                document::Document::mrz(&doc.dg1)
            );
            println!("  EOA {}", signer.address());
            println!("  shielded address pk {}", w.pk().hex());
            println!(
                "  bundle ({} chars, also in {}):",
                w.bundle.len(),
                home.join(format!("{name}.bundle")).display()
            );
            println!("{}", w.bundle);
        }
        Cmd::Identity(IdentityCmd::Show) => {
            println!("{}", Wallet::load(&home, &name()?)?.bundle);
        }
        Cmd::Identity(IdentityCmd::Register { force }) => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let r = w.register(&ctx, &p, force).await?;
            let reg = w.identity.as_ref().expect("registered");
            report(
                &format!(
                    "{}: registered (identity leaf {}, valid until {})",
                    w.name,
                    reg.index.unwrap_or_default(),
                    reg.expiry
                ),
                &r,
            );
        }
        Cmd::Contact(ContactCmd::Add {
            name: contact,
            bundle,
        }) => {
            let mut w = Wallet::load(&home, &name()?)?;
            let bytes = wallet::base64_bundle(&bundle)?;
            let sender = Sender::accept(&bytes, cli.chain_id, now(), &|_| None)
                .map_err(|e| eyre::eyre!("bundle refused: {e:?}"))?;
            println!(
                "{}: contact {contact} accepted (pk {}, valid until {})",
                w.name,
                sender.pk_b().hex(),
                sender.not_after()
            );
            w.contacts
                .insert(contact, wallet::Contact { bundle, sender });
            w.save(&home)?;
        }
        Cmd::Deposit { amount, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let (v, fee) = (wei(&amount)?, wei(&fee)?);
            let pk = w.pk();
            // The kept note is output 1 (appended at once); output 0, escrowed, is empty.
            let plan = Plan {
                ins: vec![],
                outs: [(pk, 0, false), (pk, v - fee, true)],
                v_in: v,
                v_out: 0,
                fee,
                payout: Address::ZERO,
                to: None,
            };
            let r = w.execute(plan, &ctx, &p).await?;
            report_all(&w.name, &format!("{}: deposit {} ETH", w.name, eth(v)), &r);
        }
        Cmd::Transfer { to, amount, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let (v, fee) = (wei(&amount)?, wei(&fee)?);
            let c = w
                .contacts
                .get(&to)
                .ok_or_else(|| eyre::eyre!("no contact {to} (zkpool contact add)"))?;
            let kind = if c.sender.index().is_none() {
                "handshake".to_string()
            } else {
                format!("ratchet index {}", c.sender.index().unwrap_or(0))
            };
            let pk_b = c.sender.pk_b();
            let ins = w.pick(v + fee, 2)?;
            let change = ins.iter().map(wallet::Note::value).sum::<u128>() - v - fee;
            let plan = Plan {
                ins,
                outs: [(pk_b, v, false), (w.pk(), change, true)],
                v_in: 0,
                v_out: 0,
                fee,
                payout: Address::ZERO,
                to: Some(to.clone()),
            };
            let r = w.execute(plan, &ctx, &p).await?;
            report_all(
                &w.name,
                &format!(
                    "{}: transfer {} ETH to {to} ({kind}), in escrow until {to} resolves it",
                    w.name,
                    eth(v)
                ),
                &r,
            );
        }
        Cmd::Withdraw { amount, to, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let (v, fee) = (wei(&amount)?, wei(&fee)?);
            let ins = w.pick(v + fee, 2)?;
            let change = ins.iter().map(wallet::Note::value).sum::<u128>() - v - fee;
            let pk = w.pk();
            let before = p.get_balance(to).await?;
            let plan = Plan {
                ins,
                outs: [(pk, 0, false), (pk, change, true)],
                v_in: 0,
                v_out: v,
                fee,
                payout: to,
                to: None,
            };
            let r = w.execute(plan, &ctx, &p).await?;
            report_all(
                &w.name,
                &format!("{}: withdraw {} ETH to {to}", w.name, eth(v)),
                &r,
            );
            println!(
                "  {to}: {} -> {} ETH",
                eth(before.to()),
                eth(p.get_balance(to).await?.to())
            );
        }
        Cmd::Merge { fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let fee = wei(&fee)?;
            let mut notes: Vec<_> = w
                .notes
                .iter()
                .filter(|n| n.index.is_some())
                .cloned()
                .collect();
            notes.sort_by_key(wallet::Note::value);
            eyre::ensure!(
                notes.len() >= 2,
                "merge needs two notes, the wallet has {}",
                notes.len()
            );
            let ins: Vec<_> = notes.into_iter().take(2).collect();
            let total = ins.iter().map(wallet::Note::value).sum::<u128>();
            eyre::ensure!(total >= fee, "the notes don't cover the fee");
            let pk = w.pk();
            let plan = Plan {
                ins,
                outs: [(pk, 0, false), (pk, total - fee, true)],
                v_in: 0,
                v_out: 0,
                fee,
                payout: Address::ZERO,
                to: None,
            };
            let r = w.execute(plan, &ctx, &p).await?;
            report_all(
                &w.name,
                &format!("{}: merge 2 -> 1 ({} ETH)", w.name, eth(total - fee)),
                &r,
            );
        }
        Cmd::Split { amounts, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let fee = wei(&fee)?;
            let a: Vec<u128> = amounts
                .iter()
                .map(|s| wei(s))
                .collect::<eyre::Result<_>>()?;
            let note = match a.as_slice() {
                [x] => w.pick(x + fee, 1)?.remove(0),
                [x, y] => w
                    .notes
                    .iter()
                    .find(|n| n.index.is_some() && n.value() == x + y + fee)
                    .cloned()
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "no note worth exactly {} ETH (a + b + fee); notes: {}",
                            eth(x + y + fee),
                            w.notes
                                .iter()
                                .map(|n| eth(n.value()))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })?,
                _ => eyre::bail!("--amounts a or a,b"),
            };
            let (x, y) = (a[0], note.value() - a[0] - fee);
            let pk = w.pk();
            let plan = Plan {
                ins: vec![note],
                outs: [(pk, x, true), (pk, y, true)],
                v_in: 0,
                v_out: 0,
                fee,
                payout: Address::ZERO,
                to: None,
            };
            let r = w.execute(plan, &ctx, &p).await?;
            report_all(
                &w.name,
                &format!("{}: split 1 -> 2 ({} + {} ETH)", w.name, eth(x), eth(y)),
                &r,
            );
        }
        Cmd::Notes => {
            let w = Wallet::load(&home, &name()?)?;
            println!(
                "{}: {} note(s), {} ETH",
                w.name,
                w.notes.len(),
                eth(w.balance())
            );
            for n in &w.notes {
                println!(
                    "  leaf {:>4}  {:>12} ETH  {}{}",
                    n.index.map(|i| i.to_string()).unwrap_or("-".into()),
                    eth(n.value()),
                    &n.commitment[..18],
                    n.from
                        .as_ref()
                        .map(|m| format!("  from {m}"))
                        .unwrap_or_default()
                );
            }
            for n in &w.pending {
                println!(
                    "  pending     {:>12} ETH  {}",
                    eth(n.value()),
                    &n.commitment[..18]
                );
            }
        }
        Cmd::Escrows => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            println!("{}: {} escrow(s) addressed here", w.name, w.escrows.len());
            for e in &w.escrows {
                println!(
                    "  in   {}  {:>12} ETH  {}, until {}{}",
                    &e.c0[..18],
                    eth(e.value()),
                    e.how,
                    e.deadline,
                    e.from
                        .as_ref()
                        .map(|m| format!("  from {m}"))
                        .unwrap_or_default()
                );
            }
            for s in &w.sent {
                println!(
                    "  out  {}  {:>12} ETH  {}",
                    &s.c0[..18],
                    eth(s.value.parse().unwrap_or(0)),
                    s.to.as_deref().unwrap_or("(own)")
                );
            }
        }
        Cmd::Resolve {
            escrow,
            all,
            reject,
            fee,
        } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let fee = wei(&fee)?;
            let action = if reject {
                emit_protocol::Action::Reject
            } else {
                emit_protocol::Action::Accept
            };
            let chosen: Vec<wallet::Escrow> = w
                .escrows
                .iter()
                .filter(|e| {
                    all || escrow
                        .as_ref()
                        .is_some_and(|x| e.c0.starts_with(x.as_str()))
                })
                .cloned()
                .collect();
            eyre::ensure!(
                all || chosen.len() == 1,
                "{} escrows match {}: zkpool escrows",
                chosen.len(),
                escrow.unwrap_or_default()
            );
            for e in chosen {
                let r = w.resolve(&e.c0, action, fee, &ctx, &p).await?;
                report(
                    &format!(
                        "{}: {} {} ETH ({}){}",
                        w.name,
                        if reject { "reject" } else { "accept" },
                        eth(e.value()),
                        e.how,
                        e.from.map(|m| format!(" from {m}")).unwrap_or_default()
                    ),
                    &r,
                );
            }
        }
        Cmd::Refund { escrow } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let chosen: Vec<_> = w
                .sent
                .iter()
                .filter(|s| s.c0.starts_with(escrow.as_str()))
                .cloned()
                .collect();
            let [s] = chosen.as_slice() else {
                eyre::bail!(
                    "{} sent escrows match {escrow}: zkpool escrows",
                    chosen.len()
                );
            };
            let r = w.refund(&s.c0, &ctx, &p).await?;
            report(
                &format!(
                    "{}: refund {} ETH",
                    w.name,
                    eth(s.value.parse().unwrap_or(0))
                ),
                &r,
            );
        }
        Cmd::Sync => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            let got = w.sync(&p, ctx.pool_address()?, &home).await?;
            println!(
                "{}: synced to block {} ({} leaves), {got} note(s) received into escrow, balance {} ETH, {} escrow(s) to resolve",
                w.name,
                w.synced,
                w.tree.size,
                eth(w.balance()),
                w.escrows.len()
            );
        }
        Cmd::Balance => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let signer: alloy::signers::local::PrivateKeySigner = w.key.parse()?;
            let eoa = p.get_balance(signer.address()).await?;
            println!(
                "{}: shielded {} ETH in {} note(s); EOA {} {} ETH",
                w.name,
                eth(w.balance()),
                w.notes.len(),
                signer.address(),
                eth(eoa.to())
            );
        }
        Cmd::Listen { timeout, until } => {
            use futures_util::StreamExt;
            let pool = ctx.pool_address()?;
            let p = provider().await?;
            let mut w = Wallet::load(&home, &name()?)?;
            // Subscribe first, then catch up: nothing falls between the two.
            let ws = ProviderBuilder::new()
                .connect_ws(alloy::providers::WsConnect::new(cli.ws.clone()))
                .await?;
            let sub = ws
                .subscribe_logs(&alloy::rpc::types::Filter::new().address(pool))
                .await?;
            let mut stream = sub.into_stream();
            let mut got = w.sync(&p, pool, &home).await?;
            println!("{}: listening to {pool} (block {})", w.name, w.synced);
            let deadline =
                timeout.map(|t| tokio::time::Instant::now() + std::time::Duration::from_secs(t));
            loop {
                if until.is_some_and(|u| got >= u) {
                    break;
                }
                let next = async {
                    match deadline {
                        Some(d) => tokio::time::timeout_at(d, stream.next())
                            .await
                            .ok()
                            .flatten(),
                        None => stream.next().await,
                    }
                };
                tokio::select! {
                    log = next => {
                        if log.is_none() { break; }
                        got += w.sync(&p, pool, &home).await?;
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            println!(
                "{}: stopped; {got} note(s) received into escrow, balance {} ETH",
                w.name,
                eth(w.balance())
            );
        }
    }
    Ok(())
}
