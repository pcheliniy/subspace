use crate::mock::{Header, MockStorage};
use crate::{
    BlockWeight, ChainConstants, DigestError, HashOf, HeaderExt, HeaderImporter, ImportError,
    NextDigestItems, NumberOf, RecordsRoot, SaltDerivationInfo, SegmentIndex, SolutionRange,
    Storage,
};
use frame_support::{assert_err, assert_ok};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    derive_next_global_randomness, derive_next_salt, derive_next_solution_range,
    extract_pre_digest, extract_subspace_digest_items, CompatibleDigestItem, ErrorDigestType,
    PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::testing::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::{Digest, DigestItem};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::{
    Piece, PublicKey, Randomness, Salt, Solution, Tag, PIECE_SIZE, RECORDED_HISTORY_SEGMENT_SIZE,
    RECORD_SIZE,
};
use subspace_solving::{
    create_tag, create_tag_signature, derive_global_challenge, derive_local_challenge,
    derive_target, SubspaceCodec, REWARD_SIGNING_CONTEXT,
};
use subspace_verification::{
    derive_next_eon_index, derive_next_salt_from_randomness, derive_randomness,
};

fn default_randomness_and_salt() -> (Randomness, Salt) {
    let randomness = [1u8; 32];
    let salt = [2u8; 8];
    (randomness, salt)
}

fn default_test_constants() -> ChainConstants<Header> {
    let (randomness, salt) = default_randomness_and_salt();
    ChainConstants {
        k_depth: 7,
        genesis_digest_items: NextDigestItems {
            next_global_randomness: randomness,
            next_solution_range: Default::default(),
            next_salt: salt,
        },
        max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64,
        genesis_records_roots: Default::default(),
        global_randomness_interval: 20,
        era_duration: 20,
        slot_probability: (1, 6),
        eon_duration: 20,
        next_salt_reveal_interval: 6,
    }
}

fn derive_solution_range(target: Tag, tag: Tag) -> SolutionRange {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) * 2
}

fn valid_piece(pub_key: schnorrkel::PublicKey) -> (Piece, u64, SegmentIndex, RecordsRoot) {
    // we don't care about the block data
    let mut rng = StdRng::seed_from_u64(0);
    let mut block = vec![0u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    rng.fill(block.as_mut_slice());

    let mut archiver =
        Archiver::new(RECORD_SIZE as usize, RECORDED_HISTORY_SEGMENT_SIZE as usize).unwrap();

    let archived_segment = archiver
        .add_block(block, Default::default())
        .first()
        .cloned()
        .unwrap();

    let (position, piece) = archived_segment
        .pieces
        .as_pieces()
        .enumerate()
        .collect::<Vec<(usize, &[u8])>>()
        .first()
        .cloned()
        .unwrap();

    assert!(subspace_archiving::archiver::is_piece_valid(
        piece,
        archived_segment.root_block.records_root(),
        position,
        RECORD_SIZE as usize,
    ));

    let codec = SubspaceCodec::new(pub_key.as_ref());
    let mut piece = piece.to_vec();
    codec.encode(&mut piece, position as u64).unwrap();

    (
        Piece::try_from(piece.as_slice()).unwrap(),
        position as u64,
        archived_segment.root_block.segment_index(),
        archived_segment.root_block.records_root(),
    )
}

struct ValidHeaderParams<'a> {
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &'a Keypair,
    randomness: Randomness,
    salt: Salt,
}

fn valid_header(
    params: ValidHeaderParams<'_>,
) -> (Header, SolutionRange, SegmentIndex, RecordsRoot) {
    let ValidHeaderParams {
        parent_hash,
        number,
        slot,
        keypair,
        randomness,
        salt,
    } = params;
    let (encoding, piece_index, segment_index, records_root) = valid_piece(keypair.public);
    let tag: Tag = create_tag(encoding.as_ref(), salt);
    let global_challenge = derive_global_challenge(&randomness, slot);
    let local_challenge = derive_local_challenge(keypair, global_challenge);
    let target = derive_target(
        &schnorrkel::PublicKey::from_bytes(keypair.public.as_ref()).unwrap(),
        global_challenge,
        &local_challenge,
    )
    .unwrap();
    let solution_range = derive_solution_range(target, tag);
    let tag_signature = create_tag_signature(keypair, tag);
    let digests = vec![
        DigestItem::global_randomness(randomness),
        DigestItem::solution_range(solution_range),
        DigestItem::salt(salt),
        DigestItem::subspace_pre_digest(&PreDigest {
            slot: slot.into(),
            solution: Solution {
                public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                reward_address: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                piece_index,
                encoding,
                tag_signature,
                local_challenge,
                tag,
            },
        }),
    ];

    let header = Header {
        parent_hash,
        number,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Digest { logs: digests },
    };

    (header, solution_range, segment_index, records_root)
}

fn seal_header(keypair: &Keypair, header: &mut Header) {
    let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
    let pre_hash = header.hash();
    let signature =
        FarmerSignature::unchecked_from(keypair.sign(ctx.bytes(pre_hash.as_bytes())).to_bytes());
    header
        .digest
        .logs
        .push(DigestItem::subspace_seal(signature));
}

fn remove_seal(header: &mut Header) {
    let digests = header.digest_mut();
    digests.pop();
}

fn next_slot(slot_probability: (u64, u64), current_slot: Slot) -> Slot {
    let mut rng = StdRng::seed_from_u64(current_slot.into());
    current_slot + rng.gen_range(slot_probability.0..slot_probability.1)
}

fn initialize_store(constants: ChainConstants<Header>) -> (MockStorage, HashOf<Header>) {
    let mut store = MockStorage::new(constants);
    let mut rng = StdRng::seed_from_u64(0);
    let mut state_root = vec![0u8; 32];
    rng.fill(state_root.as_mut_slice());
    let genesis_header = Header {
        parent_hash: Default::default(),
        number: 0,
        state_root: H256::from_slice(&state_root),
        extrinsics_root: Default::default(),
        digest: Default::default(),
    };

    let genesis_hash = genesis_header.hash();
    let header = HeaderExt {
        header: genesis_header,
        total_weight: 0,
        salt_derivation_info: Default::default(),
        era_start_slot: Default::default(),
        genesis_slot: Default::default(),
        test_overrides: Default::default(),
    };

    store.store_header(header, true);
    (store, genesis_hash)
}

fn add_next_digests(store: &MockStorage, number: NumberOf<Header>, header: &mut Header) {
    let constants = store.chain_constants();
    let parent_header = store.header(*header.parent_hash()).unwrap();
    let digests =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            header,
        )
        .unwrap();

    let digest_logs = header.digest_mut();
    if let Some(next_randomness) = derive_next_global_randomness::<Header>(
        number,
        constants.global_randomness_interval,
        &digests.pre_digest,
    )
    .unwrap()
    {
        digest_logs.push(DigestItem::next_global_randomness(next_randomness));
    }

    if let Some(next_solution_range) = derive_next_solution_range::<Header>(
        number,
        constants.era_duration,
        constants.slot_probability,
        digests.pre_digest.slot,
        digests.solution_range,
        parent_header.era_start_slot,
    )
    .unwrap()
    {
        digest_logs.push(DigestItem::next_solution_range(next_solution_range));
    }

    if let Some(next_salt) = derive_next_salt::<Header>(
        constants.eon_duration,
        parent_header.salt_derivation_info.eon_index,
        parent_header.genesis_slot,
        digests.pre_digest.slot,
        parent_header.salt_derivation_info.maybe_randomness,
    )
    .unwrap()
    {
        digest_logs.push(DigestItem::next_salt(next_salt));
    }
}

fn add_headers_to_chain(
    importer: &mut HeaderImporter<Header, MockStorage>,
    keypair: &Keypair,
    headers_to_add: NumberOf<Header>,
    maybe_fork_chain: Option<(HashOf<Header>, Option<bool>)>,
) -> HashOf<Header> {
    let best_header_ext = importer.store.best_header();
    let constants = importer.store.chain_constants();
    let (parent_hash, number, slot) = if let Some((parent_hash, _)) = maybe_fork_chain {
        let header = importer.store.header(parent_hash).unwrap();
        let digests = extract_pre_digest(&header.header).unwrap();

        (parent_hash, *header.header.number(), digests.slot)
    } else {
        let digests = extract_pre_digest(&best_header_ext.header).unwrap();
        (
            best_header_ext.header.hash(),
            *best_header_ext.header.number(),
            digests.slot,
        )
    };

    let until_number = number + headers_to_add;
    let mut parent_hash = parent_hash;
    let mut number = number + 1;
    let mut slot = next_slot(constants.slot_probability, slot);
    let mut best_header_hash = best_header_ext.header.hash();
    while number <= until_number {
        let (randomness, salt, override_next_solution) = if number == 1 {
            let (randomness, salt) = default_randomness_and_salt();
            (randomness, salt, false)
        } else {
            let header = importer.store.header(parent_hash).unwrap();
            let digests = extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&header.header)
            .unwrap();

            let randomness = digests
                .next_global_randomness
                .unwrap_or(digests.global_randomness);
            let salt = digests.next_salt.unwrap_or(digests.salt);
            (randomness, salt, digests.next_global_randomness.is_some())
        };

        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash,
                number,
                slot: slot.into(),
                keypair,
                randomness,
                salt,
            });
        let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
            extract_subspace_digest_items(&header).unwrap();
        let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
            &digests.global_randomness,
            &digests.pre_digest,
        );
        importer.store.override_cumulative_weight(parent_hash, 0);
        if number == 1 {
            // adjust Chain constants for Block #1
            let mut constants = importer.store.chain_constants();
            constants.genesis_digest_items.next_solution_range = solution_range;
            importer.store.override_constants(constants)
        } else if override_next_solution {
            importer
                .store
                .override_next_solution_range(parent_hash, solution_range);
        } else {
            importer
                .store
                .override_solution_range(parent_hash, solution_range);
        }
        importer
            .store
            .store_records_root(segment_index, records_root);
        if let Some((_hash, maybe_best)) = maybe_fork_chain {
            if let Some(is_best) = maybe_best {
                if is_best {
                    importer
                        .store
                        .override_cumulative_weight(best_header_hash, new_weight - 1)
                } else {
                    importer
                        .store
                        .override_cumulative_weight(best_header_hash, new_weight + 1)
                }
            } else {
                importer
                    .store
                    .override_cumulative_weight(best_header_hash, new_weight)
            }
        }

        add_next_digests(&importer.store, number, &mut header);
        seal_header(keypair, &mut header);
        parent_hash = header.hash();
        slot = next_slot(constants.slot_probability, slot);
        number += 1;

        assert_ok!(importer.import_header(header.clone()));
        if let Some((_hash, maybe_best)) = maybe_fork_chain {
            if let Some(is_best) = maybe_best {
                if is_best {
                    best_header_hash = header.hash()
                }
            }
        } else {
            best_header_hash = header.hash()
        }

        assert_eq!(importer.store.best_header().header.hash(), best_header_hash);
    }

    parent_hash
}

fn ensure_finalized_heads_have_no_forks(store: &MockStorage, finalized_number: NumberOf<Header>) {
    let finalized_header = store.finalized_header();
    let (expected_finalized_number, hash) = (
        finalized_header.header.number,
        finalized_header.header.hash(),
    );
    assert_eq!(expected_finalized_number, finalized_number);
    assert_eq!(store.headers_at_number(finalized_number).len(), 1);
    if finalized_number < 1 {
        return;
    }

    let header = store.header(hash).unwrap();
    let mut parent_hash = header.header.parent_hash;
    let mut finalized_number = finalized_number - 1;
    while finalized_number > 0 {
        assert_eq!(store.headers_at_number(finalized_number).len(), 1);
        let hash = store.headers_at_number(finalized_number)[0].header.hash();
        assert_eq!(parent_hash, hash);
        parent_hash = store.header(hash).unwrap().header.parent_hash;
        finalized_number -= 1;
    }
}

#[test]
fn test_header_import_missing_parent() {
    let constants = default_test_constants();
    let (mut store, _genesis_hash) = initialize_store(constants);
    let (randomness, salt) = default_randomness_and_salt();
    let keypair = Keypair::generate();
    let (header, _, segment_index, records_root) = valid_header(ValidHeaderParams {
        parent_hash: Default::default(),
        number: 1,
        slot: 1,
        keypair: &keypair,
        randomness,
        salt,
    });
    store.store_records_root(segment_index, records_root);
    let mut importer = HeaderImporter::new(store);
    assert_err!(
        importer.import_header(header.clone()),
        ImportError::MissingParent(header.hash())
    );
}

#[test]
fn test_header_import_non_canonical() {
    let constants = default_test_constants();
    let (store, _genesis_hash) = initialize_store(constants);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    let hash_of_2 = add_headers_to_chain(&mut importer, &keypair, 2, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_2);

    // import canonical block 3
    let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 1, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_3);
    let best_header = importer.store.header(hash_of_3).unwrap();
    assert_eq!(importer.store.headers_at_number(3).len(), 1);

    // import non canonical block 3
    add_headers_to_chain(&mut importer, &keypair, 1, Some((hash_of_2, Some(false))));

    let best_header_ext = importer.store.best_header();
    assert_eq!(best_header_ext.header, best_header.header);
    // we still track the forks
    assert_eq!(importer.store.headers_at_number(3).len(), 2);
}

#[test]
fn test_header_import_canonical() {
    let constants = default_test_constants();
    let (store, _genesis_hash) = initialize_store(constants);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_5);

    // import some more canonical blocks
    let hash_of_25 = add_headers_to_chain(&mut importer, &keypair, 20, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_25);
    assert_eq!(importer.store.headers_at_number(25).len(), 1);
}

#[test]
fn test_header_import_non_canonical_with_equal_block_weight() {
    let constants = default_test_constants();
    let (store, _genesis_hash) = initialize_store(constants);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    let hash_of_2 = add_headers_to_chain(&mut importer, &keypair, 2, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_2);

    // import canonical block 3
    let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 1, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_3);
    let best_header = importer.store.header(hash_of_3).unwrap();
    assert_eq!(importer.store.headers_at_number(3).len(), 1);

    // import non canonical block 3
    add_headers_to_chain(&mut importer, &keypair, 1, Some((hash_of_2, None)));

    let best_header_ext = importer.store.best_header();
    assert_eq!(best_header_ext.header, best_header.header);
    // we still track the forks
    assert_eq!(importer.store.headers_at_number(3).len(), 2);
}

#[test]
fn test_finalized_chain_reorg_to_longer_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let (store, genesis_hash) = initialize_store(constants);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_4);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    // create a fork chain from number 1
    add_headers_to_chain(
        &mut importer,
        &keypair,
        4,
        Some((genesis_hash, Some(false))),
    );
    assert_eq!(best_header.header.hash(), hash_of_4);
    // block 0 is still finalized
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );
    ensure_finalized_heads_have_no_forks(&importer.store, 0);

    // add new best header at 5
    let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 1, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_5);

    // block 1 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // create a fork chain from number 5 with block until 8
    let fork_hash_of_8 =
        add_headers_to_chain(&mut importer, &keypair, 4, Some((hash_of_4, Some(false))));

    // best header should still be the same
    assert_eq!(best_header.header, importer.store.best_header().header);

    // there must be 2 heads at 5
    assert_eq!(importer.store.headers_at_number(5).len(), 2);

    // block 1 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // import a new head to the fork chain and make it the best.
    let hash_of_9 = add_headers_to_chain(
        &mut importer,
        &keypair,
        1,
        Some((fork_hash_of_8, Some(true))),
    );
    assert_eq!(importer.store.best_header().header.hash(), hash_of_9);

    // now the finalized header must be 5
    ensure_finalized_heads_have_no_forks(&importer.store, 5)
}

#[test]
fn test_reorg_to_heavier_smaller_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let (store, genesis_hash) = initialize_store(constants);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_5);
    assert_eq!(importer.store.finalized_header().header.number, 1);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // now import a fork header 3 that becomes canonical
    let constants = importer.store.chain_constants();
    let header_at_2 = importer
        .store
        .headers_at_number(2)
        .first()
        .cloned()
        .unwrap();
    let digests_at_2 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_2.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_2.header.hash(),
            number: 3,
            slot: next_slot(constants.slot_probability, digests_at_2.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_2.global_randomness,
            salt: digests_at_2.salt,
        });
    seal_header(&keypair, &mut header);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
    importer
        .store
        .override_solution_range(header_at_2.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(importer.store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    importer
        .store
        .override_cumulative_weight(header_at_2.header.hash(), 0);
    let res = importer.import_header(header);
    assert_err!(res, ImportError::SwitchedToForkBelowArchivingDepth)
}

#[test]
fn test_next_digests() {
    let mut constants = default_test_constants();
    constants.global_randomness_interval = 5;
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // try to import header with out next global randomness
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    seal_header(&keypair, &mut header);
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);
    let res = importer.import_header(header.clone());
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextGlobalRandomness
        ))
    );
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // add next global randomness
    remove_seal(&mut header);
    let pre_digest = extract_pre_digest(&header).unwrap();
    let randomness = derive_randomness(
        &PublicKey::from(&pre_digest.solution.public_key),
        pre_digest.solution.tag,
        &pre_digest.solution.tag_signature,
    )
    .unwrap();
    let digests = header.digest_mut();
    digests.push(DigestItem::next_global_randomness(randomness));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextSolutionRange
        ))
    );
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // add next solution range
    remove_seal(&mut header);
    let next_solution_range = subspace_verification::derive_next_solution_range(
        u64::from(header_at_4.era_start_slot),
        u64::from(pre_digest.slot),
        constants.slot_probability,
        solution_range,
        constants
            .era_duration
            .try_into()
            .unwrap_or_else(|_| panic!("Era duration is always within u64; qed")),
    );
    let digests = header.digest_mut();
    digests.push(DigestItem::next_solution_range(next_solution_range));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header.hash(), header.hash());
}

// #[test]
// fn test_header_import_success() {
//     let mut constants = default_test_constants();
//     constants.global_randomness_interval = 11;
//     constants.era_duration = 11;
//     constants.eon_duration = 10;
//     constants.next_salt_reveal_interval = 3;
//     let mut store = MockStorage::new(constants);
//     let keypair = Keypair::generate();
//     let (parent_hash, next_slot) = import_blocks_until(&mut store, 0, 0, &keypair);
//     let best_header = store.best_header();
//     assert_eq!(best_header.header.hash(), parent_hash);
//     let mut importer = HeaderImporter::new(store);
//
//     // verify and import next headers
//     let mut slot = next_slot;
//     let mut parent_hash = parent_hash;
//     for number in 1..=10 {
//         let (header, solution_range, segment_index, records_root) =
//             valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
//         importer
//             .store
//             .override_solution_range(parent_hash, solution_range);
//         importer
//             .store
//             .store_records_root(segment_index, records_root);
//
//         let res = importer.import_header(header.clone());
//         assert_ok!(res);
//         // best header should be correct
//         let best_header = importer.store.best_header();
//         assert_eq!(best_header.header, header);
//         slot += 1;
//         parent_hash = header.hash();
//     }
//
//     // finalized head must be best 10 - 7 = 3
//     let finalized_header = importer.store.finalized_header();
//     assert_eq!(finalized_header.header.number, 3);
//
//     // header count at the finalized head must be 1
//     ensure_finalized_heads_have_no_forks(&importer.store, 3);
//
//     // verify global randomness
//     // global randomness at block number 11 should be updated as the interval is 11.
//     let (header, solution_range, segment_index, records_root) =
//         valid_header_with_default_randomness_and_salt(parent_hash, 11, slot, &keypair);
//     importer
//         .store
//         .override_solution_range(parent_hash, solution_range);
//     importer
//         .store
//         .store_records_root(segment_index, records_root);
//
//     // this should fail since the next digest for randomness is missing
//     let res = importer.import_header(header);
//     assert_err!(
//         res,
//         ImportError::DigestError(DigestError::NextDigestVerificationError(
//             ErrorDigestType::NextGlobalRandomness
//         ))
//     );
//
//     // inject expected randomness digest but should still fail due to missing next solution range
//     let (header, solution_range, segment_index, records_root) =
//         valid_header_with_next_digests(parent_hash, 11, slot, &keypair, true, None, None);
//     importer
//         .store
//         .override_solution_range(parent_hash, solution_range);
//     importer
//         .store
//         .store_records_root(segment_index, records_root);
//
//     // this should fail since the next digest for solution range is missing
//     let res = importer.import_header(header);
//     assert_err!(
//         res,
//         ImportError::DigestError(DigestError::NextDigestVerificationError(
//             ErrorDigestType::NextSolutionRange
//         ))
//     );
//
//     // inject next solution range
//     let ancestor_header = importer
//         .store
//         .headers_at_number(1)
//         .first()
//         .cloned()
//         .unwrap();
//     let ancestor_digests =
//         extract_subspace_digest_items::<Header, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
//             &ancestor_header.header,
//         )
//         .unwrap();
//
//     let constants = importer.store.chain_constants();
//     let (header, solution_range, segment_index, records_root) = valid_header_with_next_digests(
//         parent_hash,
//         11,
//         slot,
//         &keypair,
//         true,
//         Some((
//             ancestor_digests.pre_digest.slot,
//             constants.slot_probability,
//             constants.era_duration,
//         )),
//         None,
//     );
//     importer
//         .store
//         .override_solution_range(parent_hash, solution_range);
//     importer
//         .store
//         .store_records_root(segment_index, records_root);
//
//     let res = importer.import_header(header);
//     assert_err!(
//         res,
//         ImportError::DigestError(DigestError::NextDigestVerificationError(
//             ErrorDigestType::NextSalt
//         ))
//     );
//
//     // inject next salt
//     let header_at_3 = importer
//         .store
//         .headers_at_number(3)
//         .first()
//         .cloned()
//         .unwrap();
//     let header_at_4 = importer
//         .store
//         .headers_at_number(4)
//         .first()
//         .cloned()
//         .unwrap();
//
//     // verify salt reveal at block #4
//     // salt reveal number should be empty at header #3
//     assert_eq!(header_at_3.salt_derivation_info.eon_index, 0);
//     assert_eq!(header_at_3.salt_derivation_info.maybe_randomness, None);
//     // eon index should still be 0 and the next salt should be revealed at #4
//     assert_eq!(header_at_4.salt_derivation_info.eon_index, 0);
//     let digests_at_4 = extract_pre_digest(&header_at_4.header).unwrap();
//     let randomness = derive_randomness(
//         &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
//             keypair.public.to_bytes(),
//         )),
//         digests_at_4.solution.tag,
//         &digests_at_4.solution.tag_signature,
//     )
//     .unwrap();
//     assert_eq!(
//         header_at_4.salt_derivation_info.maybe_randomness,
//         Some(randomness)
//     );
//
//     let next_salt = derive_next_salt_from_randomness(0, &randomness);
//
//     // edge case when slot between #10 and #11 is long enough that, salt is revealed immediately in the first of block of next eon.
//     // so set the next slot far enough
//     slot = 15;
//     let (header, solution_range, segment_index, records_root) = valid_header_with_next_digests(
//         parent_hash,
//         11,
//         slot,
//         &keypair,
//         true,
//         Some((
//             ancestor_digests.pre_digest.slot,
//             constants.slot_probability,
//             constants.era_duration,
//         )),
//         Some(next_salt),
//     );
//     importer
//         .store
//         .override_solution_range(parent_hash, solution_range);
//     importer
//         .store
//         .store_records_root(segment_index, records_root);
//
//     let res = importer.import_header(header);
//     assert_ok!(res);
//
//     // verify eon index changes at block #11
//     let header_at_11 = importer
//         .store
//         .headers_at_number(11)
//         .first()
//         .cloned()
//         .unwrap();
//
//     // eon index should be 1
//     // since the slot is far enough, the salt should be revealed in this header as well
//     let digests_at_11 =
//         extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
//             &header_at_11.header,
//         )
//         .unwrap();
//     let randomness = derive_randomness(
//         &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
//             keypair.public.to_bytes(),
//         )),
//         digests_at_11.pre_digest.solution.tag,
//         &digests_at_11.pre_digest.solution.tag_signature,
//     )
//     .unwrap();
//     assert_eq!(header_at_11.salt_derivation_info.eon_index, 1);
//     assert_eq!(
//         header_at_11.salt_derivation_info.maybe_randomness,
//         Some(randomness)
//     );
//
//     parent_hash = header_at_11.header.hash();
//     slot += 1;
//     let (header, solution_range, segment_index, records_root) = valid_header(ValidHeaderParams {
//         parent_hash,
//         number: 12,
//         slot,
//         keypair: &keypair,
//         randomness: digests_at_11.next_global_randomness.unwrap(),
//         salt: digests_at_11.next_salt.unwrap(),
//         should_add_next_randomness: false,
//         maybe_next_solution_range: None,
//         maybe_next_salt: None,
//     });
//     importer
//         .store
//         .override_next_solution_range(parent_hash, solution_range);
//     importer
//         .store
//         .store_records_root(segment_index, records_root);
//
//     let res = importer.import_header(header.clone());
//     assert_ok!(res);
//     // best header should be correct
//     let best_header = importer.store.best_header();
//     assert_eq!(best_header.header, header);
//     // randomness should be carried over till next eon change
//     assert_eq!(best_header.salt_derivation_info.eon_index, 1);
//     assert_eq!(
//         best_header.salt_derivation_info.maybe_randomness,
//         Some(randomness)
//     );
// }
