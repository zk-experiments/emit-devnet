//! The devnet node: reth's Ethereum node (its CLI: `node --dev --chain genesis.json ...`) with an
//! EVM whose precompiles add `ZK_VERIFY` and `POSEIDON2` ([`precompiles`]). Before launching it
//! checks `pins.toml` (the catalogs fetched and hash-checked, the deployment root and pipeline
//! roots against the compiled-in registry); `--pins-offline` skips the network part.

mod precompiles;

use clap::Parser;

use alloy_evm::{
    EvmFactory,
    eth::EthEvmContext,
    precompiles::PrecompilesMap,
    revm::{context::DBErrorMarker, handler::EthPrecompiles},
};
use reth_ethereum::{
    EthPrimitives,
    chainspec::ChainSpec,
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    evm::{
        EthEvm, EthEvmConfig,
        primitives::{Database, EvmEnv},
        revm::{
            MainBuilder, MainContext,
            context::{BlockEnv, Context, TxEnv},
            context_interface::result::{EVMError, HaltReason},
            inspector::{Inspector, NoOpInspector},
            interpreter::interpreter::EthInterpreter,
            primitives::hardfork::SpecId,
        },
    },
    node::{
        EthereumNode,
        api::{FullNodeTypes, NodeTypes},
        builder::{BuilderContext, components::ExecutorBuilder},
        node::EthereumAddOns,
    },
};

/// Ethereum's EVM with the devnet's precompiles from Prague on.
#[derive(Debug, Clone, Default)]
pub struct EmitEvmFactory;

impl EvmFactory for EmitEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        EthEvm<DB, I, Self::Precompiles>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let spec = input.cfg_env.spec;
        let precompiles = if spec.is_enabled_in(SpecId::PRAGUE) {
            precompiles::prague()
        } else {
            EthPrecompiles::new(spec).precompiles
        };
        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(PrecompilesMap::from_static(precompiles));
        EthEvm::new(evm, false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        EthEvm::new(
            self.create_evm(db, input)
                .into_inner()
                .with_inspector(inspector),
            true,
        )
    }
}

/// The Ethereum executor with [`EmitEvmFactory`].
#[derive(Debug, Default, Clone, Copy)]
pub struct EmitExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for EmitExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = EthEvmConfig<ChainSpec, EmitEvmFactory>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(EthEvmConfig::new_with_evm_factory(
            ctx.chain_spec(),
            EmitEvmFactory,
        ))
    }
}

#[derive(Debug, Clone, Copy, Default, clap::Args)]
struct EmitArgs {
    /// Check only the local pins (no catalog or registry fetched).
    #[arg(long)]
    pins_offline: bool,
}

fn main() {
    Cli::<EthereumChainSpecParser, EmitArgs>::parse()
        .run(async move |builder, args| {
            let pins = emit_devnet_circuits::pins::Pins::embedded();
            let report = tokio::task::spawn_blocking(move || pins.check(args.pins_offline))
                .await?
                .map_err(|e| eyre::eyre!(e))?;
            for line in report {
                eprintln!("pins: {line}");
            }
            eprintln!(
                "precompiles: ZK_VERIFY at {} ({} gas + {}/word), POSEIDON2 at {} ({} + {}/permutation)",
                precompiles::ZK_VERIFY,
                precompiles::ZK_VERIFY_GAS,
                precompiles::ZK_VERIFY_PER_WORD,
                precompiles::POSEIDON2,
                precompiles::POSEIDON2_BASE,
                precompiles::POSEIDON2_PER_PERM
            );
            let handle = builder
                .with_types::<EthereumNode>()
                .with_components(EthereumNode::components().executor(EmitExecutorBuilder))
                .with_add_ons(EthereumAddOns::default())
                .launch_with_debug_capabilities()
                .await?;
            handle.wait_for_node_exit().await
        })
        .unwrap_or_else(|e| {
            eprintln!("emit-node: {e:?}");
            std::process::exit(1)
        });
}
