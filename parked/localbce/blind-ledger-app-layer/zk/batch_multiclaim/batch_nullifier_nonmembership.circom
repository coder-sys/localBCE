pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Multi-claim indexed-Merkle non-membership prototype.
// Ceiling label: soundness-checked, PROTOTYPE, PENDING CRYPTO AUDIT.
//
// This is intentionally isolated from the live adjudication path. For each claim
// it proves:
//   1. predecessor leaf is in the current root,
//   2. predecessor.value < nullifier < predecessor.nextValue,
//   3. predecessor is updated to point to the new nullifier,
//   4. the new insertion slot is empty under the updated-predecessor root,
//   5. the new leaf is inserted, producing the next root.
// The next claim consumes that next root, so root_0 -> ... -> root_N is chained.

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

template MerklePathToRoot(depth) {
    signal input leaf;
    signal input leafIndex;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component leafIndexBits = Num2Bits(32);
    leafIndexBits.in <== leafIndex;

    signal computedIndex[depth + 1];
    computedIndex[0] <== 0;

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hasher[depth];
    signal left[depth];
    signal right[depth];
    signal siblingMinusCur[depth];
    signal curMinusSibling[depth];

    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        computedIndex[i + 1] <== computedIndex[i] + pathIndices[i] * pow2;

        siblingMinusCur[i] <== pathElements[i] - cur[i];
        curMinusSibling[i] <== cur[i] - pathElements[i];
        left[i] <== cur[i] + pathIndices[i] * siblingMinusCur[i];
        right[i] <== pathElements[i] + pathIndices[i] * curMinusSibling[i];

        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== left[i];
        hasher[i].inputs[1] <== right[i];
        cur[i + 1] <== hasher[i].out;

        pow2 *= 2;
    }

    computedIndex[depth] === leafIndex;
    root <== cur[depth];
}

template InsertNonMemberStep(depth) {
    signal input rootBefore;
    signal input nullifier;
    signal input leafIndex;
    signal input leafValue;
    signal input nextValue;
    signal input nextIndex;
    signal input insertIndex;
    signal input predPathElements[depth];
    signal input predPathIndices[depth];
    signal input insertPathElements[depth];
    signal input insertPathIndices[depth];
    signal output rootAfter;

    component nullifierBits = Num2Bits_strict();
    nullifierBits.in <== nullifier;
    component leafValueBits = Num2Bits_strict();
    leafValueBits.in <== leafValue;
    component nextValueBits = Num2Bits_strict();
    nextValueBits.in <== nextValue;
    component nextIndexBits = Num2Bits(32);
    nextIndexBits.in <== nextIndex;
    component insertIndexBits = Num2Bits(32);
    insertIndexBits.in <== insertIndex;

    component predecessorLt = FieldLessThan();
    for (var b = 0; b < 254; b++) {
        leafValueBits.out[b] ==> predecessorLt.left[b];
        nullifierBits.out[b] ==> predecessorLt.right[b];
    }
    predecessorLt.out === 1;

    component nullifierLtSuccessor = FieldLessThan();
    for (var c = 0; c < 254; c++) {
        nullifierBits.out[c] ==> nullifierLtSuccessor.left[c];
        nextValueBits.out[c] ==> nullifierLtSuccessor.right[c];
    }
    nullifierLtSuccessor.out === 1;

    component oldLeaf = Poseidon(4);
    oldLeaf.inputs[0] <== leafValue;
    oldLeaf.inputs[1] <== nextValue;
    oldLeaf.inputs[2] <== nextIndex;
    oldLeaf.inputs[3] <== leafIndex;

    component oldPath = MerklePathToRoot(depth);
    oldPath.leaf <== oldLeaf.out;
    oldPath.leafIndex <== leafIndex;
    for (var i = 0; i < depth; i++) {
        oldPath.pathElements[i] <== predPathElements[i];
        oldPath.pathIndices[i] <== predPathIndices[i];
    }
    oldPath.root === rootBefore;

    component updatedPredLeaf = Poseidon(4);
    updatedPredLeaf.inputs[0] <== leafValue;
    updatedPredLeaf.inputs[1] <== nullifier;
    updatedPredLeaf.inputs[2] <== insertIndex;
    updatedPredLeaf.inputs[3] <== leafIndex;

    component updatedPredPath = MerklePathToRoot(depth);
    updatedPredPath.leaf <== updatedPredLeaf.out;
    updatedPredPath.leafIndex <== leafIndex;
    for (var j = 0; j < depth; j++) {
        updatedPredPath.pathElements[j] <== predPathElements[j];
        updatedPredPath.pathIndices[j] <== predPathIndices[j];
    }

    component emptyInsertPath = MerklePathToRoot(depth);
    emptyInsertPath.leaf <== 0;
    emptyInsertPath.leafIndex <== insertIndex;
    for (var k = 0; k < depth; k++) {
        emptyInsertPath.pathElements[k] <== insertPathElements[k];
        emptyInsertPath.pathIndices[k] <== insertPathIndices[k];
    }
    emptyInsertPath.root === updatedPredPath.root;

    component newLeaf = Poseidon(4);
    newLeaf.inputs[0] <== nullifier;
    newLeaf.inputs[1] <== nextValue;
    newLeaf.inputs[2] <== nextIndex;
    newLeaf.inputs[3] <== insertIndex;

    component insertedPath = MerklePathToRoot(depth);
    insertedPath.leaf <== newLeaf.out;
    insertedPath.leafIndex <== insertIndex;
    for (var m = 0; m < depth; m++) {
        insertedPath.pathElements[m] <== insertPathElements[m];
        insertedPath.pathIndices[m] <== insertPathIndices[m];
    }

    rootAfter <== insertedPath.root;
}

template BatchNullifierNonMembership(depth, nClaims) {
    signal input rootBefore;
    signal input rootAfter;
    signal input batchNullifierCommitment;

    signal input nullifiers[nClaims];
    signal input leafIndex[nClaims];
    signal input leafValue[nClaims];
    signal input nextValue[nClaims];
    signal input nextIndex[nClaims];
    signal input insertIndex[nClaims];
    signal input predPathElements[nClaims][depth];
    signal input predPathIndices[nClaims][depth];
    signal input insertPathElements[nClaims][depth];
    signal input insertPathIndices[nClaims][depth];

    signal rootChain[nClaims + 1];
    rootChain[0] <== rootBefore;

    signal commitmentChain[nClaims + 1];
    commitmentChain[0] <== 0;

    component steps[nClaims];
    component commitmentHasher[nClaims];

    for (var i = 0; i < nClaims; i++) {
        steps[i] = InsertNonMemberStep(depth);
        steps[i].rootBefore <== rootChain[i];
        steps[i].nullifier <== nullifiers[i];
        steps[i].leafIndex <== leafIndex[i];
        steps[i].leafValue <== leafValue[i];
        steps[i].nextValue <== nextValue[i];
        steps[i].nextIndex <== nextIndex[i];
        steps[i].insertIndex <== insertIndex[i];
        for (var j = 0; j < depth; j++) {
            steps[i].predPathElements[j] <== predPathElements[i][j];
            steps[i].predPathIndices[j] <== predPathIndices[i][j];
            steps[i].insertPathElements[j] <== insertPathElements[i][j];
            steps[i].insertPathIndices[j] <== insertPathIndices[i][j];
        }
        rootChain[i + 1] <== steps[i].rootAfter;

        commitmentHasher[i] = Poseidon(2);
        commitmentHasher[i].inputs[0] <== commitmentChain[i];
        commitmentHasher[i].inputs[1] <== nullifiers[i];
        commitmentChain[i + 1] <== commitmentHasher[i].out;
    }

    rootChain[nClaims] === rootAfter;
    commitmentChain[nClaims] === batchNullifierCommitment;
}
