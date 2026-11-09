pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template NullifierNonMembership(depth) {
    signal input root;
    signal input nullifier;

    signal input leafIndex;
    signal input leafValue;
    signal input nextValue;
    signal input nextIndex;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    component nullifierBits = Num2Bits(32);
    nullifierBits.in <== nullifier;
    component leafValueBits = Num2Bits(32);
    leafValueBits.in <== leafValue;
    component nextValueBits = Num2Bits(32);
    nextValueBits.in <== nextValue;
    component leafIndexBits = Num2Bits(32);
    leafIndexBits.in <== leafIndex;
    component nextIndexBits = Num2Bits(32);
    nextIndexBits.in <== nextIndex;

    component predecessorLt = LessThan(32);
    predecessorLt.in[0] <== leafValue;
    predecessorLt.in[1] <== nullifier;
    predecessorLt.out === 1;

    component nullifierLtSuccessor = LessThan(32);
    nullifierLtSuccessor.in[0] <== nullifier;
    nullifierLtSuccessor.in[1] <== nextValue;
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
