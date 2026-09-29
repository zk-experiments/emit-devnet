//! The note tree as the pool keeps it (contracts/src/IMT.sol): append-only, depth 32, Poseidon2,
//! empty leaf 0. The wallet rebuilds it from the pool's NewCommitment events.

use ark_ff::Zero;
pub use noir_zk_core::tree::Path;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::poseidon::Poseidon;
#[cfg(test)]
use zk_encryption_circuits::wallet::poseidon::FieldHex;

pub const TREE_DEPTH: usize = 32;

#[derive(Clone)]
pub struct Tree {
    zeros: Vec<Fr>,
    pub leaves: Vec<Fr>,
}

impl Default for Tree {
    fn default() -> Self {
        let mut zeros = vec![Fr::zero()];
        for l in 0..TREE_DEPTH {
            zeros.push(Poseidon::hash(&[zeros[l], zeros[l]]));
        }
        Self { zeros, leaves: vec![] }
    }
}

impl Tree {
    pub fn from_leaves(leaves: Vec<Fr>) -> Self {
        Self { leaves, ..Self::default() }
    }

    /// The path of leaf `index` (siblings from the leaf up).
    pub fn path(&self, index: u64) -> Path {
        let mut nodes = self.leaves.clone();
        let mut i = index as usize;
        let mut siblings = vec![];
        for l in 0..TREE_DEPTH {
            siblings.push(*nodes.get(i ^ 1).unwrap_or(&self.zeros[l]));
            nodes = nodes
                .chunks(2)
                .map(|p| Poseidon::hash(&[p[0], *p.get(1).unwrap_or(&self.zeros[l])]))
                .collect();
            i /= 2;
        }
        Path { index, siblings }
    }

    pub fn root(&self) -> Fr {
        self.path(0).root(*self.leaves.first().unwrap_or(&Fr::zero()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pool's EMPTY_ROOT (contracts/src/IMT.sol) is this tree's.
    #[test]
    fn empty_root_is_the_contracts() {
        assert_eq!(
            Tree::default().root().hex(),
            "0x0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d"
        );
    }
}
