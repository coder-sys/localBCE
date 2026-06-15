pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// V2 full-field note:
// V1 constrained nullifier values to 32 bits. This version uses strict 254-bit
// canonical BN254 field decompositions and compares them lexicographically, so the
// circuit nullifier can be the same full Poseidon field element as the app's
// durable duplicate key. Ceiling: soundness-checked, PENDING CRYPTO AUDIT.

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

template NullifierNonMembership(depth) {
    signal input root;
    signal input nullifier;

    signal input leafIndex;
    signal input leafValue;
    signal input nextValue;
    signal input nextIndex;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    component nullifierBits = Num2Bits_strict();
    nullifierBits.in <== nullifier;
    component leafValueBits = Num2Bits_strict();
    leafValueBits.in <== leafValue;
    component nextValueBits = Num2Bits_strict();
    nextValueBits.in <== nextValue;
    component leafIndexBits = Num2Bits(32);
    leafIndexBits.in <== leafIndex;
    component nextIndexBits = Num2Bits(32);
    nextIndexBits.in <== nextIndex;

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

    signal computedIndex[depth + 1];
    computedIndex[0] <== 0;

    component leaf = Poseidon(4);
    leaf.inputs[0] <== leafValue;
    leaf.inputs[1] <== nextValue;
    leaf.inputs[2] <== nextIndex;
    leaf.inputs[3] <== leafIndex;

    signal cur[depth + 1];
    cur[0] <== leaf.out;

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
    cur[depth] === root;
}

component main { public [root, nullifier] } = NullifierNonMembership(32);
