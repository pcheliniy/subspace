// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Verification for Subspace headers.
use crate::digests::{CompatibleDigestItem, PreDigest};
use crate::{find_pre_digest, FarmerPublicKey, FarmerSignature};
use codec::Decode;
use schnorrkel::context::SigningContext;
use schnorrkel::{PublicKey, Signature};
use sp_api::HeaderT;
use sp_consensus_slots::Slot;
use sp_runtime::DigestItem;
use subspace_consensus_primitives::ConsensusError;

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError<Header: HeaderT> {
    /// No Subspace pre-runtime digest found
    #[cfg_attr(feature = "thiserror", error("No Subspace pre-runtime digest found"))]
    NoPreRuntimeDigest,
    /// Header has a bad seal
    #[cfg_attr(feature = "thiserror", error("Header {0:?} has a bad seal"))]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[cfg_attr(feature = "thiserror", error("Header {0:?} is unsealed"))]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[cfg_attr(feature = "thiserror", error("Bad reward signature on {0:?}"))]
    BadRewardSignature(Header::Hash),
    /// Bad solution signature
    #[cfg_attr(
        feature = "thiserror",
        error("Bad solution signature on slot {0:?}: {1:?}")
    )]
    BadSolutionSignature(Slot, schnorrkel::SignatureError),
    /// Bad local challenge
    #[cfg_attr(
        feature = "thiserror",
        error("Local challenge is invalid for slot {0}: {1}")
    )]
    BadLocalChallenge(Slot, schnorrkel::SignatureError),
    /// Solution is outside of solution range
    #[cfg_attr(
        feature = "thiserror",
        error("Solution is outside of solution range for slot {0}")
    )]
    OutsideOfSolutionRange(Slot),
    /// Solution is outside of max plot size
    #[cfg_attr(
        feature = "thiserror",
        error("Solution is outside of max plot size {0}")
    )]
    OutsideOfMaxPlot(Slot),
    /// Invalid encoding of a piece
    #[cfg_attr(feature = "thiserror", error("Invalid encoding for slot {0}"))]
    InvalidEncoding(Slot),
    /// Invalid tag for salt
    #[cfg_attr(feature = "thiserror", error("Invalid tag for salt for slot {0}"))]
    InvalidTag(Slot),
    /// Consensus error
    #[cfg_attr(feature = "thiserror", error("Consensus error {1:?} at slot {0:?}"))]
    ConsensusError(Slot, ConsensusError),
}

/// A header which has been checked
pub enum CheckedHeader<H, S> {
    /// A header which has slot in the future. this is the full header (not stripped)
    /// and the slot in which it should be processed.
    Deferred(H, Slot),
    /// A header which is fully checked, including signature. This is the pre-header
    /// accompanied by the seal components.
    ///
    /// Includes the digest item that encoded the seal.
    Checked(H, S),
}

/// Subspace verification parameters
pub struct VerificationParams<'a, Header>
where
    Header: HeaderT + 'a,
{
    /// The header being verified.
    pub header: Header,
    /// The slot number of the current time.
    pub slot_now: Slot,
    /// Parameters for solution verification
    pub verify_solution_params: subspace_consensus_primitives::VerifySolutionParams<'a>,
    /// Signing context for reward signature
    pub reward_signing_context: &'a SigningContext,
}

/// Information from verified header
pub struct VerifiedHeaderInfo<RewardAddress> {
    /// Pre-digest
    pub pre_digest: PreDigest<FarmerPublicKey, RewardAddress>,
    /// Seal (signature)
    pub seal: DigestItem,
}

/// Check a header has been signed correctly and whether solution is correct. If the slot is too far
/// in the future, an error will be returned. If successful, returns the pre-header and the digest
/// item containing the seal.
///
/// The seal must be the last digest. Otherwise, the whole header is considered unsigned. This is
/// required for security and must not be changed.
///
/// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
///
/// `pre_digest` argument is optional in case it is available to avoid doing the work of extracting
/// it from the header twice.
pub fn check_header<Header, RewardAddress>(
    params: VerificationParams<Header>,
    pre_digest: Option<PreDigest<FarmerPublicKey, RewardAddress>>,
) -> Result<CheckedHeader<Header, VerifiedHeaderInfo<RewardAddress>>, VerificationError<Header>>
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    let VerificationParams {
        mut header,
        slot_now,
        verify_solution_params,
        reward_signing_context,
    } = params;

    let pre_digest = match pre_digest {
        Some(pre_digest) => pre_digest,
        None => find_pre_digest::<Header, RewardAddress>(&header)
            .ok_or(VerificationError::NoPreRuntimeDigest)?,
    };
    let slot = pre_digest.slot;

    let seal = header
        .digest_mut()
        .pop()
        .ok_or_else(|| VerificationError::HeaderUnsealed(header.hash()))?;

    let signature = seal
        .as_subspace_seal()
        .ok_or_else(|| VerificationError::HeaderBadSeal(header.hash()))?;

    // The pre-hash of the header doesn't include the seal and that's what we sign
    let pre_hash = header.hash();

    if pre_digest.slot > slot_now {
        header.digest_mut().push(seal);
        return Ok(CheckedHeader::Deferred(header, pre_digest.slot));
    }

    // Verify that block is signed properly
    if check_reward_signature(
        pre_hash.as_ref(),
        &signature,
        &pre_digest.solution.public_key,
        reward_signing_context,
    )
    .is_err()
    {
        return Err(VerificationError::BadRewardSignature(pre_hash));
    }

    // Verify that solution is valid
    subspace_consensus_primitives::verify_solution(
        &pre_digest.solution,
        verify_solution_params,
        slot,
    )
    .map_err(|err| VerificationError::ConsensusError(slot, err))?;

    Ok(CheckedHeader::Checked(
        header,
        VerifiedHeaderInfo { pre_digest, seal },
    ))
}

/// Check the reward signature validity.
pub fn check_reward_signature(
    hash: &[u8],
    signature: &FarmerSignature,
    public_key: &FarmerPublicKey,
    reward_signing_context: &SigningContext,
) -> Result<(), schnorrkel::SignatureError> {
    let public_key = PublicKey::from_bytes(public_key.as_ref())?;
    let signature = Signature::from_bytes(signature)?;
    public_key.verify(reward_signing_context.bytes(hash), &signature)
}
