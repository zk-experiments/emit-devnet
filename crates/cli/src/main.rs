//! `zkpool`: the devnet's console wallet. See README.md for the flow.

mod chain;
mod document;
mod emit;
mod tree;
mod wallet;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use clap::{Parser, Subcommand};
use emit_devnet_circuits::setup::Pool;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use wallet::{Plan, Wallet};
use zk_encryption_circuits::wallet::poseidon::FieldHex;
use zk_encryption_circuits::wallet::sender::Sender;

/// The devnet's known dev keys (the standard test mnemonic's accounts 1 and 2): Alice's and Bob's
/// funded EOAs (genesis.json). Account 0 deploys.
const DEV_KEYS: [(&str, &str); 2] = [
    ("alice", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
    ("bob", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
];

#[derive(Parser)]
#[command(name = "zkpool", about = "Console wallet for the Emit V2 devnet")]
struct Cli {
    /// Where wallets are kept (`<name>.json`).
    #[arg(long, env = "ZKPOOL_HOME", global = true)]
    home: Option<PathBuf>,
    #[arg(long, env = "ZKPOOL_RPC", default_value = "http://127.0.0.1:8545", global = true)]
    rpc: String,
    #[arg(long, env = "ZKPOOL_WS", default_value = "ws://127.0.0.1:8546", global = true)]
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
    /// Follows the pool live (a log subscription), printing received notes.
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
        self.pool.ok_or_else(|| eyre::eyre!("no pool address (--pool or ZKPOOL_POOL)"))
    }

    pub fn registry(&self) -> eyre::Result<&csca_registry::output::Registry> {
        if self.registry.get().is_none() {
            let _ = self.registry.set(document::registry()?);
        }
        Ok(self.registry.get().expect("set"))
    }

    /// The proving pool for these eid circuits: the pins checked (catalogs fetched), then eid's
    /// packs downloaded and its document step compiled if not cached.
    pub fn pool(&self, labels: &[String; 3]) -> eyre::Result<&Pool> {
        if self.artifacts.get().is_none() {
            let pins = emit_devnet_circuits::pins::Pins::embedded();
            let checks = pins.check(false).map_err(|e| eyre::eyre!(e))?;
            eprintln!("pins: {} checks ok", checks.len());
            let labels: BTreeSet<String> = labels.iter().cloned().collect();
            let pool = emit_devnet_circuits::setup::pool(&pins, &labels, &|l| eprintln!("setup: {l}"))
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
        "{what}: proved in {:.2} s ({} B proof, verified locally in {:.0} ms), transact gas {} ({} B calldata), block {}, tx {}",
        r.prove_s, r.proof_bytes, r.verify_ms, r.gas_used, r.calldata, r.block, r.tx
    );
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
    let name = || cli.wallet.clone().ok_or_else(|| eyre::eyre!("which wallet? (--wallet or ZKPOOL_WALLET)"));
    let provider = || async { Ok::<_, eyre::Report>(ProviderBuilder::new().connect(&cli.rpc).await?) };

    match cli.cmd {
        Cmd::Info { check } => {
            use emit_devnet_circuits::circuits::{DEPLOYMENT_ROOT, pipelines};
            let pins = emit_devnet_circuits::pins::Pins::embedded();
            let reg = ctx.registry()?;
            println!("deployment_root   {}", emit_devnet_circuits::hex32(&DEPLOYMENT_ROOT));
            println!("identity_transfer {}", emit_devnet_circuits::hex32(&pipelines::identity_transfer::ROOT));
            println!("transfer_only     {}", emit_devnet_circuits::hex32(&pipelines::transfer_only::ROOT));
            println!("fixtures_registry {}", document::registry_root(reg).hex());
            println!("csca_registry     {} ({})", pins.csca.root, pins.csca.tag);
            for line in pins.check(!check).map_err(|e| eyre::eyre!(e))? {
                println!("pins: {line}");
            }
        }
        Cmd::Identity(IdentityCmd::New { name, document, key, force }) => {
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
            println!("identity {name}: passport {document} ({})", document::Document::mrz(&doc.dg1));
            println!("  EOA {}", signer.address());
            println!("  shielded address pk {}", w.pk().hex());
            println!("  bundle ({} chars, also in {}):", w.bundle.len(), home.join(format!("{name}.bundle")).display());
            println!("{}", w.bundle);
        }
        Cmd::Identity(IdentityCmd::Show) => {
            println!("{}", Wallet::load(&home, &name()?)?.bundle);
        }
        Cmd::Contact(ContactCmd::Add { name: contact, bundle }) => {
            let mut w = Wallet::load(&home, &name()?)?;
            use base64::Engine;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(bundle.trim())
                .map_err(|e| eyre::eyre!("bundle: not base64url: {e}"))?;
            let sender = Sender::accept(&bytes, cli.chain_id, now(), &|_| None)
                .map_err(|e| eyre::eyre!("bundle refused: {e:?}"))?;
            println!("{}: contact {contact} accepted (pk {}, valid until {})", w.name, sender.pk_b().hex(), sender.not_after());
            w.contacts.insert(contact, wallet::Contact { bundle, sender });
            w.save(&home)?;
        }
        Cmd::Deposit { amount, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let (v, fee) = (wei(&amount)?, wei(&fee)?);
            let pk = w.pk();
            let plan = Plan { ins: vec![], outs: [(pk, v - fee, true), (pk, 0, false)], v_in: v, v_out: 0, fee, payout: Address::ZERO, to: None };
            let r = w.execute(plan, &ctx, &p).await?;
            report(&format!("{}: deposit {} ETH", w.name, eth(v)), &r);
        }
        Cmd::Transfer { to, amount, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let (v, fee) = (wei(&amount)?, wei(&fee)?);
            let c = w.contacts.get(&to).ok_or_else(|| eyre::eyre!("no contact {to} (zkpool contact add)"))?;
            let kind = if c.sender.index().is_none() { "handshake".to_string() } else { format!("ratchet index {}", c.sender.index().unwrap_or(0)) };
            let pk_b = c.sender.pk_b();
            let ins = w.pick(v + fee, 2)?;
            let change = ins.iter().map(wallet::Note::value).sum::<u128>() - v - fee;
            let plan = Plan { ins, outs: [(pk_b, v, false), (w.pk(), change, true)], v_in: 0, v_out: 0, fee, payout: Address::ZERO, to: Some(to.clone()) };
            let r = w.execute(plan, &ctx, &p).await?;
            report(&format!("{}: transfer {} ETH to {to} ({kind})", w.name, eth(v)), &r);
        }
        Cmd::Withdraw { amount, to, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let (v, fee) = (wei(&amount)?, wei(&fee)?);
            let ins = w.pick(v + fee, 2)?;
            let change = ins.iter().map(wallet::Note::value).sum::<u128>() - v - fee;
            let pk = w.pk();
            let before = p.get_balance(to).await?;
            let plan = Plan { ins, outs: [(pk, change, true), (pk, 0, false)], v_in: 0, v_out: v, fee, payout: to, to: None };
            let r = w.execute(plan, &ctx, &p).await?;
            report(&format!("{}: withdraw {} ETH to {to}", w.name, eth(v)), &r);
            println!("  {to}: {} -> {} ETH", eth(before.to()), eth(p.get_balance(to).await?.to()));
        }
        Cmd::Merge { fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let fee = wei(&fee)?;
            let mut notes: Vec<_> = w.notes.iter().filter(|n| n.index.is_some()).cloned().collect();
            notes.sort_by_key(wallet::Note::value);
            eyre::ensure!(notes.len() >= 2, "merge needs two notes, the wallet has {}", notes.len());
            let ins: Vec<_> = notes.into_iter().take(2).collect();
            let total = ins.iter().map(wallet::Note::value).sum::<u128>();
            eyre::ensure!(total >= fee, "the notes don't cover the fee");
            let pk = w.pk();
            let plan = Plan { ins, outs: [(pk, total - fee, true), (pk, 0, false)], v_in: 0, v_out: 0, fee, payout: Address::ZERO, to: None };
            let r = w.execute(plan, &ctx, &p).await?;
            report(&format!("{}: merge 2 -> 1 ({} ETH)", w.name, eth(total - fee)), &r);
        }
        Cmd::Split { amounts, fee } => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            w.sync(&p, ctx.pool_address()?, &home).await?;
            let fee = wei(&fee)?;
            let a: Vec<u128> = amounts.iter().map(|s| wei(s)).collect::<eyre::Result<_>>()?;
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
                            w.notes.iter().map(|n| eth(n.value())).collect::<Vec<_>>().join(", ")
                        )
                    })?,
                _ => eyre::bail!("--amounts a or a,b"),
            };
            let (x, y) = (a[0], note.value() - a[0] - fee);
            let pk = w.pk();
            let plan = Plan { ins: vec![note], outs: [(pk, x, true), (pk, y, true)], v_in: 0, v_out: 0, fee, payout: Address::ZERO, to: None };
            let r = w.execute(plan, &ctx, &p).await?;
            report(&format!("{}: split 1 -> 2 ({} + {} ETH)", w.name, eth(x), eth(y)), &r);
        }
        Cmd::Notes => {
            let w = Wallet::load(&home, &name()?)?;
            println!("{}: {} note(s), {} ETH", w.name, w.notes.len(), eth(w.balance()));
            for n in &w.notes {
                println!(
                    "  leaf {:>4}  {:>12} ETH  {}{}",
                    n.index.map(|i| i.to_string()).unwrap_or("-".into()),
                    eth(n.value()),
                    &n.commitment[..18],
                    n.from.as_ref().map(|m| format!("  from {m}")).unwrap_or_default()
                );
            }
            for n in &w.pending {
                println!("  pending     {:>12} ETH  {}", eth(n.value()), &n.commitment[..18]);
            }
        }
        Cmd::Sync => {
            let (p, mut w) = (provider().await?, Wallet::load(&home, &name()?)?);
            let got = w.sync(&p, ctx.pool_address()?, &home).await?;
            println!("{}: synced to block {} ({} leaves), {got} note(s) received, balance {} ETH", w.name, w.synced, w.leaves.len(), eth(w.balance()));
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
            let mut got = w.sync(&p, pool, &home).await?;
            let ws = ProviderBuilder::new().connect_ws(alloy::providers::WsConnect::new(cli.ws.clone())).await?;
            let sub = ws.subscribe_logs(&alloy::rpc::types::Filter::new().address(pool)).await?;
            let mut stream = sub.into_stream();
            println!("{}: listening to {pool} (block {})", w.name, w.synced);
            let deadline = timeout.map(|t| tokio::time::Instant::now() + std::time::Duration::from_secs(t));
            loop {
                if until.is_some_and(|u| got >= u) {
                    break;
                }
                let next = async {
                    match deadline {
                        Some(d) => tokio::time::timeout_at(d, stream.next()).await.ok().flatten(),
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
            println!("{}: stopped; {got} note(s) received, balance {} ETH", w.name, eth(w.balance()));
        }
    }
    Ok(())
}
