pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template ClaimAdjudicationCore() {
    signal input memberId;
    signal input providerNpi;
    signal input eligibilityActive;
    signal input providerEnrolled;
    signal input serviceLineCount;
    signal input diagnosisCount;
    signal input priorAuthOk;
    signal input chargeCents;
    signal input maxChargeCents;
    signal input duplicateFlag;
    signal input programIntegrityHold;
    signal input claimNonce;

    signal input claimCommitment;
    signal input nullifier;
    signal input decision;
    signal input failureCode;

    component commitment = Poseidon(11);
    commitment.inputs[0] <== memberId;
    commitment.inputs[1] <== providerNpi;
    commitment.inputs[2] <== eligibilityActive;
    commitment.inputs[3] <== providerEnrolled;
    commitment.inputs[4] <== serviceLineCount;
    commitment.inputs[5] <== diagnosisCount;
    commitment.inputs[6] <== priorAuthOk;
    commitment.inputs[7] <== chargeCents;
    commitment.inputs[8] <== maxChargeCents;
    commitment.inputs[9] <== duplicateFlag;
    commitment.inputs[10] <== programIntegrityHold;
    commitment.out === claimCommitment;

    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== memberId;
    nullifierHash.inputs[1] <== claimNonce;
    nullifierHash.out === nullifier;

    eligibilityActive * (eligibilityActive - 1) === 0;
    providerEnrolled * (providerEnrolled - 1) === 0;
    priorAuthOk * (priorAuthOk - 1) === 0;
    duplicateFlag * (duplicateFlag - 1) === 0;
    programIntegrityHold * (programIntegrityHold - 1) === 0;

    component memberPresent = GreaterThan(64);
    memberPresent.in[0] <== memberId;
    memberPresent.in[1] <== 0;

    component providerPresent = GreaterThan(64);
    providerPresent.in[0] <== providerNpi;
    providerPresent.in[1] <== 0;

    component serviceLinePresent = GreaterThan(32);
    serviceLinePresent.in[0] <== serviceLineCount;
    serviceLinePresent.in[1] <== 0;

    component diagnosisPresent = GreaterThan(32);
    diagnosisPresent.in[0] <== diagnosisCount;
    diagnosisPresent.in[1] <== 0;

    component chargePositive = GreaterThan(64);
    chargePositive.in[0] <== chargeCents;
    chargePositive.in[1] <== 0;

    component chargeWithinMax = LessEqThan(64);
    chargeWithinMax.in[0] <== chargeCents;
    chargeWithinMax.in[1] <== maxChargeCents;

    signal gate[10];
    gate[0] <== memberPresent.out;
    gate[1] <== eligibilityActive;
    gate[2] <== providerPresent.out;
    gate[3] <== providerEnrolled;
    gate[4] <== serviceLinePresent.out;
    gate[5] <== diagnosisPresent.out;
    gate[6] <== priorAuthOk;
    gate[7] <== chargePositive.out * chargeWithinMax.out;
    gate[8] <== 1 - duplicateFlag;
    gate[9] <== 1 - programIntegrityHold;

    signal prefixPass[11];
    prefixPass[0] <== 1;

    signal firstFailure[10];
    signal weightedFailure[10];
    signal failureSum[11];
    failureSum[0] <== 0;

    for (var i = 0; i < 10; i++) {
        firstFailure[i] <== prefixPass[i] * (1 - gate[i]);
        weightedFailure[i] <== firstFailure[i] * (i + 1);
        failureSum[i + 1] <== failureSum[i] + weightedFailure[i];
        prefixPass[i + 1] <== prefixPass[i] * gate[i];
    }

    decision === prefixPass[10];
    failureCode === failureSum[10];
}

component main { public [claimCommitment, nullifier, decision, failureCode] } = ClaimAdjudicationCore();
