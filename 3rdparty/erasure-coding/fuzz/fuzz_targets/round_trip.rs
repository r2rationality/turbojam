#![no_main]

use erasure_coding::*;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: (Vec<u8>, u16)| {
	let n_chunks = data.1.max(1).min(2048);
	let data = data.0;
	if data.is_empty() || data.len() > 1 * 1024 * 1024 {
		return;
	}
	let chunks = construct_chunks(n_chunks, &data).unwrap();
	assert_eq!(chunks.len() as u16, n_chunks);

	let threshold = systematic_recovery_threshold(n_chunks).unwrap();
	let reconstructed_systematic: Vec<u8> = reconstruct_from_systematic(
		n_chunks,
		chunks.len(),
		&mut chunks.iter().map(Vec::as_slice),
		data.len(),
	)
	.unwrap();

	let threshold = recovery_threshold(n_chunks).unwrap();
	let map: HashMap<ChunkIndex, Vec<u8>> = chunks
		.into_iter()
		.enumerate()
		.map(|(i, v)| (ChunkIndex::from(i as u16), v))
		.collect();
	let some_chunks = map.into_iter().take(threshold as usize);
	let reconstructed: Vec<u8> = reconstruct(n_chunks, some_chunks, data.len()).unwrap();

	assert_eq!(reconstructed, data);
	assert_eq!(reconstructed_systematic, data);
});
