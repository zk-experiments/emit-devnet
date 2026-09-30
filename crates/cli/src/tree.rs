//! The note tree as the pool keeps it (contracts/src/IMT.sol): append-only, depth 32, Poseidon2,
//! empty leaf 0. The wallet follows it from the pool's events without keeping the leaves: it keeps
//! the frontier (the last left node at each height, the contract's `filled`) and the path of each
//! leaf it watches (its own notes, its registration), updating those paths as leaves are appended.
//! An append costs 32 hashes plus a comparison per watched leaf and height; a watched leaf costs
//! 32 fields (~1 KB of JSON), whatever the size of the tree.

use ark_ff::Zero;
pub use noir_zk_core::tree::Path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::poseidon::{FieldHex, Poseidon};

pub const TREE_DEPTH: usize = 32;

/// The roots of the empty subtrees: zeros[0] = 0, zeros[h + 1] = H(zeros[h], zeros[h]).
fn zeros() -> &'static [Fr; TREE_DEPTH + 1] {
    static Z: OnceLock<[Fr; TREE_DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [Fr::zero(); TREE_DEPTH + 1];
        for h in 0..TREE_DEPTH {
            z[h + 1] = Poseidon::hash(&[z[h], z[h]]);
        }
        z
    })
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "Stored", from = "Stored")]
pub struct Tree {
    /// The number of leaves appended.
    pub size: u64,
    filled: [Fr; TREE_DEPTH],
    root: Fr,
    /// The watched leaves' siblings, from the leaf up, by leaf index.
    watched: BTreeMap<u64, [Fr; TREE_DEPTH]>,
}

impl Default for Tree {
    fn default() -> Self {
        Self {
            size: 0,
            filled: [Fr::zero(); TREE_DEPTH],
            root: zeros()[TREE_DEPTH],
            watched: BTreeMap::new(),
        }
    }
}

impl Tree {
    /// Appends `leaf` (the pool's next index), keeping its path if `watch`; returns its index.
    pub fn append(&mut self, leaf: Fr, watch: bool) -> u64 {
        let index = self.size;
        let z = zeros();
        // At its insertion everything right of the new leaf is empty: its left siblings are the
        // frontier, its right ones empty subtrees.
        let own: [Fr; TREE_DEPTH] = std::array::from_fn(|h| {
            if (index >> h) & 1 == 1 {
                self.filled[h]
            } else {
                z[h]
            }
        });
        let mut node = leaf;
        for h in 0..TREE_DEPTH {
            // `node` is now the root of the height-h subtree holding the new leaf: the sibling at
            // height h of every watched leaf in the subtree next to it.
            for (i, path) in &mut self.watched {
                if (i >> h) ^ 1 == index >> h {
                    path[h] = node;
                }
            }
            node = if (index >> h) & 1 == 0 {
                self.filled[h] = node;
                Poseidon::hash(&[node, z[h]])
            } else {
                Poseidon::hash(&[self.filled[h], node])
            };
        }
        self.root = node;
        self.size += 1;
        if watch {
            self.watched.insert(index, own);
        }
        index
    }

    /// The path of a watched leaf (siblings from the leaf up), under the current root.
    pub fn path(&self, index: u64) -> Option<Path> {
        self.watched.get(&index).map(|s| Path {
            index,
            siblings: s.to_vec(),
        })
    }

    /// Stops following a leaf (a spent note, a replaced registration).
    pub fn unwatch(&mut self, index: u64) {
        self.watched.remove(&index);
    }

    pub fn root(&self) -> Fr {
        self.root
    }
}

/// The JSON form: fields as hex.
#[derive(Serialize, Deserialize)]
struct Stored {
    size: u64,
    filled: Vec<String>,
    root: String,
    watched: BTreeMap<u64, Vec<String>>,
}

fn fields(v: &[String]) -> [Fr; TREE_DEPTH] {
    std::array::from_fn(|h| v.get(h).map(|s| Fr::from_hex(s)).unwrap_or_default())
}

impl From<Tree> for Stored {
    fn from(t: Tree) -> Self {
        let hex = |a: &[Fr; TREE_DEPTH]| a.iter().map(|f| f.hex()).collect();
        Self {
            size: t.size,
            filled: hex(&t.filled),
            root: t.root.hex(),
            watched: t.watched.iter().map(|(i, p)| (*i, hex(p))).collect(),
        }
    }
}

impl From<Stored> for Tree {
    fn from(s: Stored) -> Self {
        Self {
            size: s.size,
            filled: fields(&s.filled),
            root: Fr::from_hex(&s.root),
            watched: s.watched.iter().map(|(i, p)| (*i, fields(p))).collect(),
        }
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

    /// The tree rebuilt from all its leaves: the root, and the path of leaf `index`.
    fn rebuilt(leaves: &[Fr], index: u64) -> (Fr, Vec<Fr>) {
        let z = zeros();
        let (mut nodes, mut i, mut siblings) = (leaves.to_vec(), index as usize, vec![]);
        for zero in &z[..TREE_DEPTH] {
            siblings.push(*nodes.get(i ^ 1).unwrap_or(zero));
            nodes = nodes
                .chunks(2)
                .map(|p| Poseidon::hash(&[p[0], *p.get(1).unwrap_or(zero)]))
                .collect();
            i /= 2;
        }
        (nodes.first().copied().unwrap_or(z[TREE_DEPTH]), siblings)
    }

    /// Watched paths kept up to date leaf by leaf equal the paths of the whole tree rebuilt, and
    /// survive a JSON round trip.
    #[test]
    fn incremental_paths_match_the_rebuilt_tree() {
        let mut t = Tree::default();
        let mut leaves = vec![];
        let watch = [0u64, 1, 5, 8, 12, 13];
        for i in 0..21u64 {
            let leaf = Fr::from(1000 + i);
            leaves.push(leaf);
            assert_eq!(t.append(leaf, watch.contains(&i)), i);
            if i == 12 {
                t.unwatch(1);
            }
            t = serde_json::from_str(&serde_json::to_string(&t).expect("json")).expect("json");
            for &w in watch.iter().filter(|&&w| w <= i) {
                let (root, siblings) = rebuilt(&leaves, w);
                assert_eq!(t.root(), root);
                match t.path(w) {
                    Some(p) => {
                        assert_eq!(p.siblings, siblings, "leaf {w} after {i}");
                        assert_eq!(p.root(leaves[w as usize]), root);
                    }
                    None => assert!(w == 1 && i >= 12),
                }
            }
        }
        assert!(t.path(2).is_none(), "not watched");
    }
}
