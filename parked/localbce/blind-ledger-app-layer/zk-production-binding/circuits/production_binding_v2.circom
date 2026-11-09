pragma circom 2.2.3;

include "../../zk/node_modules/circomlib/circuits/poseidon.circom";
include "../../zk/node_modules/circomlib/circuits/comparators.circom";
include "../../zk/node_modules/circomlib/circuits/bitify.circom";

/*
  Production binding v2.

  This circuit closes the v0 "prover-chosen root" holes and the v1
  free-claim-story gap:
  - normalized claim facts must be included under a trusted claimSourceRoot,
  - oracle facts must be included under a governed oracleFactsRoot,
  - fee / prior-auth policy rows must be included under a governed feeScheduleRoot,
  - recipient must be included under a governed addressBookRoot,
  - nullifier must be derived from the claim-source leaf and inserted into an
    empty sparse slot,
  - amount/date fields are range constrained,
  - payment uses the fee allowed amount, not the billed amount.

  Ceiling label: soundness-checked by compile/witness tests, PENDING CRYPTO AUDIT.
*/

template Bool() {
    signal input in;
    in * (in - 1) === 0;
}

template FieldLessThan() {
    signal input left[254];
    signal input right[254];
    signal output out;

    signal eq[255];
    signal lt[255];
    signal lessAt[254];
    signal eqBit[254];

    eq[0] <== 1;
    lt[0] <== 0;

    for (var i = 0; i < 254; i++) {
        var bit = 253 - i;
        lessAt[i] <== (1 - left[bit]) * right[bit];
        eqBit[i] <== 1 - left[bit] - right[bit] + 2 * left[bit] * right[bit];
        lt[i + 1] <== lt[i] + eq[i] * lessAt[i];
        eq[i + 1] <== eq[i] * eqBit[i];
    }

    out <== lt[254];
}

template MerkleInclusion(depth) {
    signal input leaf;
    signal input root;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hasher[depth];
    signal left[depth];
    signal right[depth];
    signal siblingMinusCur[depth];
    signal curMinusSibling[depth];

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        siblingMinusCur[i] <== pathElements[i] - cur[i];
        curMinusSibling[i] <== cur[i] - pathElements[i];
        left[i] <== cur[i] + pathIndices[i] * siblingMinusCur[i];
        right[i] <== pathElements[i] + pathIndices[i] * curMinusSibling[i];

        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== left[i];
        hasher[i].inputs[1] <== right[i];
        cur[i + 1] <== hasher[i].out;
    }

    cur[depth] === root;
}

template MerkleUpdate(depth) {
    signal input oldLeaf;
    signal input newLeaf;
    signal input oldRoot;
    signal output newRoot;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal oldCur[depth + 1];
    signal newCur[depth + 1];
    oldCur[0] <== oldLeaf;
    newCur[0] <== newLeaf;

    component oldHasher[depth];
    component newHasher[depth];
    signal oldLeft[depth];
    signal oldRight[depth];
    signal newLeft[depth];
    signal newRight[depth];
    signal oldSiblingMinusCur[depth];
    signal oldCurMinusSibling[depth];
    signal newSiblingMinusCur[depth];
    signal newCurMinusSibling[depth];

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        oldSiblingMinusCur[i] <== pathElements[i] - oldCur[i];
        oldCurMinusSibling[i] <== oldCur[i] - pathElements[i];
        oldLeft[i] <== oldCur[i] + pathIndices[i] * oldSiblingMinusCur[i];
        oldRight[i] <== pathElements[i] + pathIndices[i] * oldCurMinusSibling[i];

        newSiblingMinusCur[i] <== pathElements[i] - newCur[i];
        newCurMinusSibling[i] <== newCur[i] - pathElements[i];
        newLeft[i] <== newCur[i] + pathIndices[i] * newSiblingMinusCur[i];
        newRight[i] <== pathElements[i] + pathIndices[i] * newCurMinusSibling[i];

        oldHasher[i] = Poseidon(2);
        oldHasher[i].inputs[0] <== oldLeft[i];
        oldHasher[i].inputs[1] <== oldRight[i];
        oldCur[i + 1] <== oldHasher[i].out;

        newHasher[i] = Poseidon(2);
        newHasher[i].inputs[0] <== newLeft[i];
        newHasher[i].inputs[1] <== newRight[i];
        newCur[i + 1] <== newHasher[i].out;
    }

    oldCur[depth] === oldRoot;
    newRoot <== newCur[depth];
}

template IndexedNullifierInsert(depth) {
    signal input rootBefore;
    signal input rootAfter;
    signal input nullifier;

    signal input predecessorValue;
    signal input successorValue;
    signal input predecessorIndex;
    signal input successorIndex;
    signal input predecessorPathElements[depth];
    signal input predecessorPathIndices[depth];
    signal input insertPathElements[depth];
    signal input insertPathIndices[depth];

    component nullifierBits = Num2Bits_strict();
    nullifierBits.in <== nullifier;
    component predecessorBits = Num2Bits_strict();
    predecessorBits.in <== predecessorValue;
    component successorBits = Num2Bits_strict();
    successorBits.in <== successorValue;
    component predecessorIndexBits = Num2Bits(32);
    predecessorIndexBits.in <== predecessorIndex;
    component successorIndexBits = Num2Bits(32);
    successorIndexBits.in <== successorIndex;

    component predecessorLtNullifier = FieldLessThan();
    component nullifierLtSuccessor = FieldLessThan();
    for (var b = 0; b < 254; b++) {
        predecessorBits.out[b] ==> predecessorLtNullifier.left[b];
        nullifierBits.out[b] ==> predecessorLtNullifier.right[b];
        nullifierBits.out[b] ==> nullifierLtSuccessor.left[b];
        successorBits.out[b] ==> nullifierLtSuccessor.right[b];
    }
    predecessorLtNullifier.out === 1;
    nullifierLtSuccessor.out === 1;

    signal computedPredecessorIndex[depth + 1];
    signal computedInsertIndex[depth + 1];
    computedPredecessorIndex[0] <== 0;
    computedInsertIndex[0] <== 0;

    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        predecessorPathIndices[i] * (predecessorPathIndices[i] - 1) === 0;
        insertPathIndices[i] * (insertPathIndices[i] - 1) === 0;
        computedPredecessorIndex[i + 1] <== computedPredecessorIndex[i] + predecessorPathIndices[i] * pow2;
        computedInsertIndex[i + 1] <== computedInsertIndex[i] + insertPathIndices[i] * pow2;
        insertPathIndices[i] === nullifierBits.out[i];
        pow2 *= 2;
    }

    computedPredecessorIndex[depth] === predecessorIndex;

    component sameIndex = IsEqual();
    sameIndex.in[0] <== computedInsertIndex[depth];
    sameIndex.in[1] <== predecessorIndex;
    sameIndex.out === 0;

    component oldPredLeaf = Poseidon(4);
    oldPredLeaf.inputs[0] <== predecessorValue;
    oldPredLeaf.inputs[1] <== successorValue;
    oldPredLeaf.inputs[2] <== successorIndex;
    oldPredLeaf.inputs[3] <== predecessorIndex;

    component updatedPredLeaf = Poseidon(4);
    updatedPredLeaf.inputs[0] <== predecessorValue;
    updatedPredLeaf.inputs[1] <== nullifier;
    updatedPredLeaf.inputs[2] <== computedInsertIndex[depth];
    updatedPredLeaf.inputs[3] <== predecessorIndex;

    component updatePredecessor = MerkleUpdate(depth);
    updatePredecessor.oldLeaf <== oldPredLeaf.out;
    updatePredecessor.newLeaf <== updatedPredLeaf.out;
    updatePredecessor.oldRoot <== rootBefore;
    for (var p = 0; p < depth; p++) {
        updatePredecessor.pathElements[p] <== predecessorPathElements[p];
        updatePredecessor.pathIndices[p] <== predecessorPathIndices[p];
    }

    component emptyInsertLeaf = Poseidon(4);
    emptyInsertLeaf.inputs[0] <== 0;
    emptyInsertLeaf.inputs[1] <== 0;
    emptyInsertLeaf.inputs[2] <== 0;
    emptyInsertLeaf.inputs[3] <== computedInsertIndex[depth];

    component insertedLeaf = Poseidon(4);
    insertedLeaf.inputs[0] <== nullifier;
    insertedLeaf.inputs[1] <== successorValue;
    insertedLeaf.inputs[2] <== successorIndex;
    insertedLeaf.inputs[3] <== computedInsertIndex[depth];

    component insertNullifier = MerkleUpdate(depth);
    insertNullifier.oldLeaf <== emptyInsertLeaf.out;
    insertNullifier.newLeaf <== insertedLeaf.out;
    insertNullifier.oldRoot <== updatePredecessor.newRoot;
    for (var q = 0; q < depth; q++) {
        insertNullifier.pathElements[q] <== insertPathElements[q];
        insertNullifier.pathIndices[q] <== insertPathIndices[q];
    }
    insertNullifier.newRoot === rootAfter;
}

template ProductionBindingV2(depth) {
    // Public roots/outputs.
    signal input rawClaimHash;
    signal input claimSourceRoot;
    signal input oracleSignerRoot;
    signal input oracleFactsRoot;
    signal input feeScheduleRoot;
    signal input addressBookRoot;
    signal input rulesetRoot;
    signal input nullifierRootBefore;
    signal input nullifierRootAfter;
    signal input claimRoot;
    signal input resultRoot;
    signal input paymentRoot;
    signal input combinedCommitment;
    signal input decision;
    signal input failureCode;
    signal input paymentAmountCents;
    signal input recipientField;
    signal input verifierKeyId;

    // Private normalized claim and governed fact row values.
    signal input memberKey;
    signal input providerKey;
    signal input memberIdPresent;
    signal input eligibilityActive;
    signal input providerNpiPresent;
    signal input providerEnrolled;
    signal input providerNotSuspended;
    signal input notDeceased;
    signal input serviceLinesPresent;
    signal input diagnosisPresent;
    signal input priorAuthRequired;
    signal input priorAuthValid;
    signal input noProgramIntegrityHold;
    signal input serviceDate;
    signal input procedureCode;
    signal input totalChargeCents;
    signal input lineChargeCents;
    signal input feeEffectiveFrom;
    signal input feeEffectiveUntil;
    signal input feeAllowedAmountCents;
    signal input addressBookVersion;
    signal input predecessorNullifier;
    signal input successorNullifier;
    signal input predecessorIndex;
    signal input successorIndex;

    signal input claimSourcePathElements[depth];
    signal input claimSourcePathIndices[depth];
    signal input oraclePathElements[depth];
    signal input oraclePathIndices[depth];
    signal input feePathElements[depth];
    signal input feePathIndices[depth];
    signal input addressPathElements[depth];
    signal input addressPathIndices[depth];
    signal input predecessorPathElements[depth];
    signal input predecessorPathIndices[depth];
    signal input insertPathElements[depth];
    signal input insertPathIndices[depth];

    component bools[13];
    bools[0] = Bool();
    bools[0].in <== memberIdPresent;
    bools[1] = Bool();
    bools[1].in <== eligibilityActive;
    bools[2] = Bool();
    bools[2].in <== providerNpiPresent;
    bools[3] = Bool();
    bools[3].in <== providerEnrolled;
    bools[4] = Bool();
    bools[4].in <== providerNotSuspended;
    bools[5] = Bool();
    bools[5].in <== notDeceased;
    bools[6] = Bool();
    bools[6].in <== serviceLinesPresent;
    bools[7] = Bool();
    bools[7].in <== diagnosisPresent;
    bools[8] = Bool();
    bools[8].in <== priorAuthRequired;
    bools[9] = Bool();
    bools[9].in <== priorAuthValid;
    bools[10] = Bool();
    bools[10].in <== noProgramIntegrityHold;
    bools[11] = Bool();
    bools[11].in <== decision;

    component serviceDateBits = Num2Bits(32);
    serviceDateBits.in <== serviceDate;
    component totalChargeBits = Num2Bits(32);
    totalChargeBits.in <== totalChargeCents;
    component lineChargeBits = Num2Bits(32);
    lineChargeBits.in <== lineChargeCents;
    component feeAllowedBits = Num2Bits(32);
    feeAllowedBits.in <== feeAllowedAmountCents;
    component feeStartBits = Num2Bits(32);
    feeStartBits.in <== feeEffectiveFrom;
    component feeEndBits = Num2Bits(32);
    feeEndBits.in <== feeEffectiveUntil;

    component claimSourceLeaf = Poseidon(11);
    claimSourceLeaf.inputs[0] <== rawClaimHash;
    claimSourceLeaf.inputs[1] <== memberKey;
    claimSourceLeaf.inputs[2] <== providerKey;
    claimSourceLeaf.inputs[3] <== memberIdPresent;
    claimSourceLeaf.inputs[4] <== providerNpiPresent;
    claimSourceLeaf.inputs[5] <== serviceLinesPresent;
    claimSourceLeaf.inputs[6] <== diagnosisPresent;
    claimSourceLeaf.inputs[7] <== totalChargeCents;
    claimSourceLeaf.inputs[8] <== lineChargeCents;
    claimSourceLeaf.inputs[9] <== serviceDate;
    claimSourceLeaf.inputs[10] <== procedureCode;

    component claimSourceMembership = MerkleInclusion(depth);
    claimSourceMembership.leaf <== claimSourceLeaf.out;
    claimSourceMembership.root <== claimSourceRoot;
    for (var c = 0; c < depth; c++) {
        claimSourceMembership.pathElements[c] <== claimSourcePathElements[c];
        claimSourceMembership.pathIndices[c] <== claimSourcePathIndices[c];
    }

    component nullifierHash = Poseidon(5);
    nullifierHash.inputs[0] <== claimSourceLeaf.out;
    nullifierHash.inputs[1] <== memberKey;
    nullifierHash.inputs[2] <== providerKey;
    nullifierHash.inputs[3] <== serviceDate;
    nullifierHash.inputs[4] <== procedureCode;

    component nullifierInsert = IndexedNullifierInsert(depth);
    nullifierInsert.rootBefore <== nullifierRootBefore;
    nullifierInsert.rootAfter <== nullifierRootAfter;
    nullifierInsert.nullifier <== nullifierHash.out;
    nullifierInsert.predecessorValue <== predecessorNullifier;
    nullifierInsert.successorValue <== successorNullifier;
    nullifierInsert.predecessorIndex <== predecessorIndex;
    nullifierInsert.successorIndex <== successorIndex;
    for (var n = 0; n < depth; n++) {
        nullifierInsert.predecessorPathElements[n] <== predecessorPathElements[n];
        nullifierInsert.predecessorPathIndices[n] <== predecessorPathIndices[n];
        nullifierInsert.insertPathElements[n] <== insertPathElements[n];
        nullifierInsert.insertPathIndices[n] <== insertPathIndices[n];
    }

    component oracleLeaf = Poseidon(9);
    oracleLeaf.inputs[0] <== memberKey;
    oracleLeaf.inputs[1] <== providerKey;
    oracleLeaf.inputs[2] <== serviceDate;
    oracleLeaf.inputs[3] <== eligibilityActive;
    oracleLeaf.inputs[4] <== providerEnrolled;
    oracleLeaf.inputs[5] <== providerNotSuspended;
    oracleLeaf.inputs[6] <== notDeceased;
    oracleLeaf.inputs[7] <== priorAuthValid;
    oracleLeaf.inputs[8] <== oracleSignerRoot;

    component oracleMembership = MerkleInclusion(depth);
    oracleMembership.leaf <== oracleLeaf.out;
    oracleMembership.root <== oracleFactsRoot;
    for (var o = 0; o < depth; o++) {
        oracleMembership.pathElements[o] <== oraclePathElements[o];
        oracleMembership.pathIndices[o] <== oraclePathIndices[o];
    }

    component feeLeaf = Poseidon(7);
    feeLeaf.inputs[0] <== procedureCode;
    feeLeaf.inputs[1] <== feeEffectiveFrom;
    feeLeaf.inputs[2] <== feeEffectiveUntil;
    feeLeaf.inputs[3] <== feeAllowedAmountCents;
    feeLeaf.inputs[4] <== priorAuthRequired;
    feeLeaf.inputs[5] <== rulesetRoot;
    feeLeaf.inputs[6] <== oracleSignerRoot;

    component feeMembership = MerkleInclusion(depth);
    feeMembership.leaf <== feeLeaf.out;
    feeMembership.root <== feeScheduleRoot;
    for (var f = 0; f < depth; f++) {
        feeMembership.pathElements[f] <== feePathElements[f];
        feeMembership.pathIndices[f] <== feePathIndices[f];
    }

    component addressLeaf = Poseidon(3);
    addressLeaf.inputs[0] <== providerKey;
    addressLeaf.inputs[1] <== recipientField;
    addressLeaf.inputs[2] <== addressBookVersion;

    component addressMembership = MerkleInclusion(depth);
    addressMembership.leaf <== addressLeaf.out;
    addressMembership.root <== addressBookRoot;
    for (var a = 0; a < depth; a++) {
        addressMembership.pathElements[a] <== addressPathElements[a];
        addressMembership.pathIndices[a] <== addressPathIndices[a];
    }

    component serviceDateAfterFeeStart = GreaterEqThan(32);
    serviceDateAfterFeeStart.in[0] <== serviceDate;
    serviceDateAfterFeeStart.in[1] <== feeEffectiveFrom;

    component serviceDateBeforeFeeEnd = LessEqThan(32);
    serviceDateBeforeFeeEnd.in[0] <== serviceDate;
    serviceDateBeforeFeeEnd.in[1] <== feeEffectiveUntil;

    component chargePositive = GreaterThan(32);
    chargePositive.in[0] <== totalChargeCents;
    chargePositive.in[1] <== 0;

    component lineChargePositive = GreaterThan(32);
    lineChargePositive.in[0] <== lineChargeCents;
    lineChargePositive.in[1] <== 0;

    component chargeWithinAllowed = LessEqThan(32);
    chargeWithinAllowed.in[0] <== lineChargeCents;
    chargeWithinAllowed.in[1] <== feeAllowedAmountCents;

    totalChargeCents === lineChargeCents;

    signal gate[11];
    gate[0] <== memberIdPresent;
    gate[1] <== eligibilityActive * notDeceased;
    gate[2] <== providerNpiPresent;
    gate[3] <== providerEnrolled * providerNotSuspended;
    gate[4] <== serviceLinesPresent;
    gate[5] <== diagnosisPresent;
    gate[6] <== 1 - priorAuthRequired * (1 - priorAuthValid);
    signal positiveChargePair;
    signal serviceDateInRange;
    positiveChargePair <== chargePositive.out * lineChargePositive.out;
    serviceDateInRange <== serviceDateAfterFeeStart.out * serviceDateBeforeFeeEnd.out;
    gate[7] <== positiveChargePair * serviceDateInRange;
    gate[8] <== chargeWithinAllowed.out;
    gate[9] <== 1;
    gate[10] <== noProgramIntegrityHold;

    signal prefix[12];
    prefix[0] <== 1;
    for (var i = 0; i < 11; i++) {
        prefix[i + 1] <== prefix[i] * gate[i];
    }

    decision === prefix[11];

    signal failureParts[11];
    failureParts[0] <== (1 - gate[0]) * prefix[0] * 1;
    failureParts[1] <== (1 - gate[1]) * prefix[1] * 2;
    failureParts[2] <== (1 - gate[2]) * prefix[2] * 3;
    failureParts[3] <== (1 - gate[3]) * prefix[3] * 4;
    failureParts[4] <== (1 - gate[4]) * prefix[4] * 5;
    failureParts[5] <== (1 - gate[5]) * prefix[5] * 6;
    failureParts[6] <== (1 - gate[6]) * prefix[6] * 7;
    failureParts[7] <== (1 - gate[7]) * prefix[7] * 81;
    failureParts[8] <== (1 - gate[8]) * prefix[8] * 82;
    failureParts[9] <== (1 - gate[9]) * prefix[9] * 9;
    failureParts[10] <== (1 - gate[10]) * prefix[10] * 10;

    failureCode === failureParts[0] + failureParts[1] + failureParts[2] + failureParts[3] + failureParts[4] + failureParts[5] + failureParts[6] + failureParts[7] + failureParts[8] + failureParts[9] + failureParts[10];

    paymentAmountCents === decision * feeAllowedAmountCents;

    component claimRootHash = Poseidon(1);
    claimRootHash.inputs[0] <== claimSourceLeaf.out;
    claimRoot === claimRootHash.out;

    component resultHash = Poseidon(9);
    resultHash.inputs[0] <== decision;
    resultHash.inputs[1] <== failureCode;
    resultHash.inputs[2] <== paymentAmountCents;
    resultHash.inputs[3] <== claimSourceRoot;
    resultHash.inputs[4] <== oracleFactsRoot;
    resultHash.inputs[5] <== feeScheduleRoot;
    resultHash.inputs[6] <== addressBookRoot;
    resultHash.inputs[7] <== rulesetRoot;
    resultHash.inputs[8] <== nullifierHash.out;
    resultRoot === resultHash.out;

    component paymentLeafHash = Poseidon(4);
    paymentLeafHash.inputs[0] <== providerKey;
    paymentLeafHash.inputs[1] <== recipientField;
    paymentLeafHash.inputs[2] <== paymentAmountCents;
    paymentLeafHash.inputs[3] <== resultRoot;

    component approvedPaymentRootHash = Poseidon(1);
    approvedPaymentRootHash.inputs[0] <== paymentLeafHash.out;
    paymentRoot === decision * approvedPaymentRootHash.out;

    component combinedHash = Poseidon(14);
    combinedHash.inputs[0] <== claimRoot;
    combinedHash.inputs[1] <== resultRoot;
    combinedHash.inputs[2] <== paymentRoot;
    combinedHash.inputs[3] <== nullifierRootBefore;
    combinedHash.inputs[4] <== nullifierRootAfter;
    combinedHash.inputs[5] <== claimSourceRoot;
    combinedHash.inputs[6] <== oracleFactsRoot;
    combinedHash.inputs[7] <== oracleSignerRoot;
    combinedHash.inputs[8] <== feeScheduleRoot;
    combinedHash.inputs[9] <== addressBookRoot;
    combinedHash.inputs[10] <== rulesetRoot;
    combinedHash.inputs[11] <== verifierKeyId;
    combinedHash.inputs[12] <== decision;
    combinedHash.inputs[13] <== paymentAmountCents;
    combinedCommitment === combinedHash.out;
}

component main { public [
    rawClaimHash,
    claimSourceRoot,
    oracleSignerRoot,
    oracleFactsRoot,
    feeScheduleRoot,
    addressBookRoot,
    rulesetRoot,
    nullifierRootBefore,
    nullifierRootAfter,
    claimRoot,
    resultRoot,
    paymentRoot,
    combinedCommitment,
    decision,
    failureCode,
    paymentAmountCents,
    recipientField,
    verifierKeyId
] } = ProductionBindingV2(10);
