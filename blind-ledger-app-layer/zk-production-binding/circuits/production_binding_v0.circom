pragma circom 2.2.3;

include "../../zk/node_modules/circomlib/circuits/poseidon.circom";
include "../../zk/node_modules/circomlib/circuits/comparators.circom";

/*
  Production binding v0.

  This circuit binds one normalized claim to:
  - a raw-claim digest,
  - oracle fact root,
  - fee schedule row root,
  - adjudication gate result,
  - payment/nullifier transition roots,
  - one combined public commitment.

  It is intentionally separate from the frozen Groth16 adjudication circuit.
  It does not verify Ed25519 signatures or parse raw 837 text in-circuit.
*/

template Bool() {
    signal input in;
    in * (in - 1) === 0;
}

template ProductionBindingV0() {
    // Public values.
    signal input rawClaimHash;
    signal input oracleSignerRoot;
    signal input oracleFactsRoot;
    signal input feeRoot;
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

    // Private normalized claim facts.
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
    signal input duplicateNotSeen;
    signal input noProgramIntegrityHold;
    signal input serviceDate;
    signal input procedureCode;
    signal input totalChargeCents;
    signal input lineChargeCents;
    signal input feeEffectiveFrom;
    signal input feeEffectiveUntil;
    signal input feeMaxChargeCents;
    signal input nullifier;

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
    bools[10].in <== duplicateNotSeen;
    bools[11] = Bool();
    bools[11].in <== noProgramIntegrityHold;
    bools[12] = Bool();
    bools[12].in <== decision;

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

    component chargeWithinFee = LessEqThan(32);
    chargeWithinFee.in[0] <== lineChargeCents;
    chargeWithinFee.in[1] <== feeMaxChargeCents;

    totalChargeCents === lineChargeCents;

    // Oracle facts and fee schedule row are committed inside the proof.
    component oracleHash = Poseidon(6);
    oracleHash.inputs[0] <== eligibilityActive;
    oracleHash.inputs[1] <== providerEnrolled;
    oracleHash.inputs[2] <== providerNotSuspended;
    oracleHash.inputs[3] <== notDeceased;
    oracleHash.inputs[4] <== priorAuthValid;
    oracleHash.inputs[5] <== oracleSignerRoot;
    oracleFactsRoot === oracleHash.out;

    component feeHash = Poseidon(4);
    feeHash.inputs[0] <== procedureCode;
    feeHash.inputs[1] <== feeEffectiveFrom;
    feeHash.inputs[2] <== feeEffectiveUntil;
    feeHash.inputs[3] <== feeMaxChargeCents;
    feeRoot === feeHash.out;

    // G1-G10 plus a G8 split: G8a invalid/nonpositive charge, G8b charge exceeds fee.
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
    gate[8] <== chargeWithinFee.out;
    gate[9] <== duplicateNotSeen;
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

    paymentAmountCents === decision * totalChargeCents;

    component claimLeafHash = Poseidon(9);
    claimLeafHash.inputs[0] <== rawClaimHash;
    claimLeafHash.inputs[1] <== memberIdPresent;
    claimLeafHash.inputs[2] <== providerNpiPresent;
    claimLeafHash.inputs[3] <== serviceLinesPresent;
    claimLeafHash.inputs[4] <== diagnosisPresent;
    claimLeafHash.inputs[5] <== totalChargeCents;
    claimLeafHash.inputs[6] <== lineChargeCents;
    claimLeafHash.inputs[7] <== serviceDate;
    claimLeafHash.inputs[8] <== procedureCode;

    component claimRootHash = Poseidon(1);
    claimRootHash.inputs[0] <== claimLeafHash.out;
    claimRoot === claimRootHash.out;

    component resultHash = Poseidon(6);
    resultHash.inputs[0] <== decision;
    resultHash.inputs[1] <== failureCode;
    resultHash.inputs[2] <== paymentAmountCents;
    resultHash.inputs[3] <== oracleFactsRoot;
    resultHash.inputs[4] <== feeRoot;
    resultHash.inputs[5] <== rulesetRoot;
    resultRoot === resultHash.out;

    component paymentLeafHash = Poseidon(3);
    paymentLeafHash.inputs[0] <== recipientField;
    paymentLeafHash.inputs[1] <== paymentAmountCents;
    paymentLeafHash.inputs[2] <== resultRoot;

    component approvedPaymentRootHash = Poseidon(1);
    approvedPaymentRootHash.inputs[0] <== paymentLeafHash.out;
    paymentRoot === decision * approvedPaymentRootHash.out;

    component insertedNullifierRootHash = Poseidon(2);
    insertedNullifierRootHash.inputs[0] <== nullifierRootBefore;
    insertedNullifierRootHash.inputs[1] <== nullifier;
    signal approvedNullifierRoot;
    signal deniedNullifierRoot;
    approvedNullifierRoot <== decision * insertedNullifierRootHash.out;
    deniedNullifierRoot <== (1 - decision) * nullifierRootBefore;
    nullifierRootAfter === approvedNullifierRoot + deniedNullifierRoot;

    component combinedHash = Poseidon(12);
    combinedHash.inputs[0] <== claimRoot;
    combinedHash.inputs[1] <== resultRoot;
    combinedHash.inputs[2] <== paymentRoot;
    combinedHash.inputs[3] <== nullifierRootBefore;
    combinedHash.inputs[4] <== nullifierRootAfter;
    combinedHash.inputs[5] <== oracleFactsRoot;
    combinedHash.inputs[6] <== oracleSignerRoot;
    combinedHash.inputs[7] <== feeRoot;
    combinedHash.inputs[8] <== rulesetRoot;
    combinedHash.inputs[9] <== verifierKeyId;
    combinedHash.inputs[10] <== decision;
    combinedHash.inputs[11] <== paymentAmountCents;
    combinedCommitment === combinedHash.out;
}

component main { public [
    rawClaimHash,
    oracleSignerRoot,
    oracleFactsRoot,
    feeRoot,
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
] } = ProductionBindingV0();
