use std::collections::VecDeque;

use crate::{ChunkIndex, ErasureChunk, Error};
use bounded_collections::{BoundedVec, ConstU32};
use scale::{Decode, Encode};

use blake2b_simd::{blake2b as hash_fn, Hash as InnerHash, State as InnerHasher};

// Binary Merkle Tree with 16-bit `ChunkIndex` has depth at most 17.
// The proof has at most `depth - 1` length.
const MAX_MERKLE_PROOF_DEPTH: u32 = 16;

/// The root of the erasure chunks that can be used to verify chunk proofs.
#[derive(PartialEq, Eq, Clone, Debug, Hash, PartialOrd, Ord, Encode, Decode)]
pub struct ErasureRoot(Hash);

impl From<Hash> for ErasureRoot {
	fn from(hash: Hash) -> Self {
		ErasureRoot(hash)
	}
}

impl From<[u8; 32]> for ErasureRoot {
	fn from(hash: [u8; 32]) -> Self {
		ErasureRoot(Hash(hash))
	}
}

impl From<ErasureRoot> for [u8; 32] {
	fn from(root: ErasureRoot) -> Self {
		root.0 .0
	}
}

#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy, Debug, Encode, Decode, Default)]
struct Hash([u8; 32]);

impl From<InnerHash> for Hash {
	fn from(hash: InnerHash) -> Self {
		let mut output = [0u8; 32];
		output.copy_from_slice(&hash.as_array()[..32]);
		Hash(output)
	}
}

/// Proof of an erasure chunk which can be verified against [`ErasureRoot`].
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct Proof(BoundedVec<Hash, ConstU32<MAX_MERKLE_PROOF_DEPTH>>);

impl Proof {
	/// Approximate allocated size for proof.
	pub fn alloc_mem(&self) -> usize {
		self.0.len() * std::mem::size_of::<Hash>()
	}
}

impl TryFrom<MerklePath> for Proof {
	type Error = Error;

	fn try_from(input: MerklePath) -> Result<Self, Self::Error> {
		Ok(Proof(BoundedVec::try_from(input).map_err(|_| Error::TooLargeProof)?))
	}
}

/// Yields all erasure chunks as an iterator.
pub struct MerklizedChunks {
	root: ErasureRoot,
	data: VecDeque<Vec<u8>>,
	// This is a Binary Merkle Tree,
	// where each level is a vector of hashes starting from leaves.
	// ```
	// 0 -> [c, d, e, Hash::zero()]
	// 1 -> [a = hash(c, d), b = hash(e, Hash::zero())]
	// 2 -> hash(a, b)
	// ```
	// Levels are guaranteed to have a power of 2 elements.
	// Leaves might be padded with `Hash::zero()`.
	tree: Vec<Vec<Hash>>,
	// Used by the iterator implementation.
	current_index: ChunkIndex,
}

// This is what is actually stored in a `Proof`.
type MerklePath = Vec<Hash>;

impl MerklizedChunks {
	/// Get the erasure root.
	pub fn root(&self) -> ErasureRoot {
		self.root.clone()
	}
}

impl Iterator for MerklizedChunks {
	type Item = ErasureChunk;

	fn next(&mut self) -> Option<Self::Item> {
		let chunk = self.data.pop_front()?;
		let d = self.tree.len() - 1;
		let idx = self.current_index.0;
		let mut index = idx as usize;
		let mut path = Vec::with_capacity(d);
		for i in 0..d {
			let layer = &self.tree[i];
			if index % 2 == 0 {
				path.push(layer[index + 1]);
			} else {
				path.push(layer[index - 1]);
			}
			index /= 2;
		}
		self.current_index += 1;
		Some(ErasureChunk {
			chunk,
			proof: Proof::try_from(path).expect("the path is limited by tree depth; qed"),
			index: ChunkIndex(idx),
		})
	}
}

impl MerklizedChunks {
	/// Compute `MerklizedChunks` from a list of erasure chunks.
	pub fn compute(chunks: Vec<Vec<u8>>) -> Self {
		let mut hashes: Vec<Hash> = chunks
			.iter()
			.map(|chunk| {
				let hash = hash_fn(chunk);
				Hash::from(hash)
			})
			.collect();
		hashes.resize(chunks.len().next_power_of_two(), Hash::default());

		let depth = hashes.len().ilog2() as usize + 1;
		let mut tree = vec![Vec::new(); depth];
		tree[0] = hashes;

		// Build the tree bottom-up.
		(1..depth).for_each(|lvl| {
			let len = 2usize.pow((depth - 1 - lvl) as u32);
			tree[lvl].resize(len, Hash::default());

			// NOTE: This can be parallelized.
			(0..len).for_each(|i| {
				let prev = &tree[lvl - 1];

				let hash = combine(prev[2 * i], prev[2 * i + 1]);

				tree[lvl][i] = hash;
			});
		});

		assert!(tree[tree.len() - 1].len() == 1, "root must be a single hash");

		Self {
			root: ErasureRoot::from(tree[tree.len() - 1][0]),
			data: chunks.into(),
			tree,
			current_index: ChunkIndex::from(0),
		}
	}
}

fn combine(left: Hash, right: Hash) -> Hash {
	let mut hasher = InnerHasher::new();

	hasher.update(left.0.as_slice());
	hasher.update(right.0.as_slice());

	let inner_hash: InnerHash = hasher.finalize();

	inner_hash.into()
}

impl ErasureChunk {
	/// Verify the proof of the chunk against the erasure root and index.
	pub fn verify(&self, root: &ErasureRoot) -> bool {
		let leaf_hash = Hash::from(hash_fn(&self.chunk));
		let bits = Bitfield(self.index.0);

		let root_hash = self.proof.0.iter().fold((leaf_hash, 0), |(acc, i), hash| {
			let (a, b) = if bits.get_bit(i) { (*hash, acc) } else { (acc, *hash) };
			(combine(a, b), i + 1)
		});

		// check the index doesn't contain more bits than the proof length
		let index_bits = 16 - self.index.0.leading_zeros() as usize;
		index_bits <= self.proof.0.len() && root_hash.0 == root.0
	}
}

struct Bitfield(u16);

impl Bitfield {
	/// Get the bit at the given index.
	pub fn get_bit(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn zero_chunks_works() {
		let chunks = vec![];
		let iter = MerklizedChunks::compute(chunks.clone());
		let root = iter.root();
		let erasure_chunks: Vec<ErasureChunk> = iter.collect();
		assert_eq!(erasure_chunks.len(), chunks.len());
		assert_eq!(root, ErasureRoot(Hash::default()));
	}

	#[test]
	fn iter_works() {
		let chunks = vec![vec![1], vec![2], vec![3]];
		let iter = MerklizedChunks::compute(chunks.clone());
		let root = iter.root();
		let erasure_chunks: Vec<ErasureChunk> = iter.collect();
		assert_eq!(erasure_chunks.len(), chunks.len());

		// compute the proof manually
		let proof_0 = {
			let a0 = hash_fn(&chunks[0]).into();
			let a1 = hash_fn(&chunks[1]).into();
			let a2 = hash_fn(&chunks[2]).into();
			let a3 = Hash::default();

			let b0 = combine(a0, a1);
			let b1 = combine(a2, a3);

			let c0 = combine(b0, b1);

			assert_eq!(c0, root.0);

			let p = vec![a1, b1];
			Proof::try_from(p).unwrap()
		};

		assert_eq!(erasure_chunks[0].proof, proof_0);

		let invalid_1 = ErasureChunk {
			chunk: erasure_chunks[0].chunk.clone(),
			proof: erasure_chunks[0].proof.clone(),
			index: ChunkIndex(erasure_chunks[0].index.0 + 1),
		};

		let invalid_2 = ErasureChunk {
			chunk: erasure_chunks[0].chunk.clone(),
			proof: erasure_chunks[0].proof.clone(),
			index: ChunkIndex(erasure_chunks[0].index.0 | 1 << 15),
		};

		assert!(!invalid_1.verify(&root));
		assert!(!invalid_2.verify(&root));

		for chunk in erasure_chunks {
			assert!(chunk.verify(&root));
		}
	}
}
