"use strict";

const fs = require("fs");
const path = require("path");

const circomlibjs = require("../../zk/node_modules/circomlibjs");

const OUT_DIR = path.join(__dirname, "..", "inputs");

function asBigInt(value) {
  return BigInt(value);
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;
  const hash = (...values) => F.toString(poseidon(values.map(asBigInt)));

  const base = {
    rawClaimHash: "1001001001001",
    oracleSignerRoot: "424242424242",
    rulesetRoot: "900100200300",
    nullifierRootBefore: "707070707070",
    decision: "1",
    failureCode: "0",
    recipientField: "515151515151",
    verifierKeyId: "1",
    memberIdPresent: "1",
    eligibilityActive: "1",
    providerNpiPresent: "1",
    providerEnrolled: "1",
    providerNotSuspended: "1",
    notDeceased: "1",
    serviceLinesPresent: "1",
    diagnosisPresent: "1",
    priorAuthRequired: "0",
    priorAuthValid: "1",
    duplicateNotSeen: "1",
    noProgramIntegrityHold: "1",
    serviceDate: "20260601",
    procedureCode: "99213",
    totalChargeCents: "12500",
    lineChargeCents: "12500",
    feeEffectiveFrom: "20260101",
    feeEffectiveUntil: "20261231",
    feeMaxChargeCents: "50000",
    nullifier: "777777777777"
  };

  const firstFailureCode = (v) => {
    const gates = [
      BigInt(v.memberIdPresent),
      BigInt(v.eligibilityActive) * BigInt(v.notDeceased),
      BigInt(v.providerNpiPresent),
      BigInt(v.providerEnrolled) * BigInt(v.providerNotSuspended),
      BigInt(v.serviceLinesPresent),
      BigInt(v.diagnosisPresent),
      1n - BigInt(v.priorAuthRequired) * (1n - BigInt(v.priorAuthValid)),
      (BigInt(v.totalChargeCents) > 0n &&
       BigInt(v.lineChargeCents) > 0n &&
       BigInt(v.serviceDate) >= BigInt(v.feeEffectiveFrom) &&
       BigInt(v.serviceDate) <= BigInt(v.feeEffectiveUntil)) ? 1n : 0n,
      BigInt(v.lineChargeCents) <= BigInt(v.feeMaxChargeCents) ? 1n : 0n,
      BigInt(v.duplicateNotSeen),
      BigInt(v.noProgramIntegrityHold)
    ];
    const codes = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 81n, 82n, 9n, 10n];
    for (let i = 0; i < gates.length; i += 1) {
      if (gates[i] === 0n) return codes[i].toString();
    }
    return "0";
  };

  function finalize(input, options = {}) {
    const v = clone(input);
    const failureCode = options.forceFailureCode ?? firstFailureCode(v);
    const decision = options.forceDecision ?? (failureCode === "0" ? "1" : "0");
    const paymentAmountCents = options.forcePaymentAmountCents ?? (decision === "1" ? v.totalChargeCents : "0");

    v.decision = decision;
    v.failureCode = failureCode;
    v.paymentAmountCents = paymentAmountCents;
    v.oracleFactsRoot = hash(
      v.eligibilityActive,
      v.providerEnrolled,
      v.providerNotSuspended,
      v.notDeceased,
      v.priorAuthValid,
      v.oracleSignerRoot
    );
    v.feeRoot = hash(v.procedureCode, v.feeEffectiveFrom, v.feeEffectiveUntil, v.feeMaxChargeCents);
    const claimLeaf = hash(
      v.rawClaimHash,
      v.memberIdPresent,
      v.providerNpiPresent,
      v.serviceLinesPresent,
      v.diagnosisPresent,
      v.totalChargeCents,
      v.lineChargeCents,
      v.serviceDate,
      v.procedureCode
    );
    v.claimRoot = hash(claimLeaf);
    v.resultRoot = hash(v.decision, v.failureCode, v.paymentAmountCents, v.oracleFactsRoot, v.feeRoot, v.rulesetRoot);
    const paymentLeaf = hash(v.recipientField, v.paymentAmountCents, v.resultRoot);
    v.paymentRoot = v.decision === "1" ? hash(paymentLeaf) : "0";
    const insertedNullifierRoot = hash(v.nullifierRootBefore, v.nullifier);
    v.nullifierRootAfter = v.decision === "1" ? insertedNullifierRoot : v.nullifierRootBefore;
    v.combinedCommitment = hash(
      v.claimRoot,
      v.resultRoot,
      v.paymentRoot,
      v.nullifierRootBefore,
      v.nullifierRootAfter,
      v.oracleFactsRoot,
      v.oracleSignerRoot,
      v.feeRoot,
      v.rulesetRoot,
      v.verifierKeyId,
      v.decision,
      v.paymentAmountCents
    );
    return v;
  }

  const approved = finalize(base);
  fs.writeFileSync(path.join(OUT_DIR, "approved.json"), JSON.stringify(approved, null, 2));

  const duplicateDenied = finalize({ ...base, duplicateNotSeen: "0" });
  fs.writeFileSync(path.join(OUT_DIR, "duplicate_denied.json"), JSON.stringify(duplicateDenied, null, 2));

  const tamperedOracleRoot = clone(approved);
  tamperedOracleRoot.oracleFactsRoot = "123456789";
  fs.writeFileSync(path.join(OUT_DIR, "tampered_oracle_root.json"), JSON.stringify(tamperedOracleRoot, null, 2));

  const feeTooLowButForcedApproved = finalize(
    { ...base, feeMaxChargeCents: "1000" },
    { forceDecision: "1", forceFailureCode: "0", forcePaymentAmountCents: base.totalChargeCents }
  );
  fs.writeFileSync(path.join(OUT_DIR, "fee_too_low_forced_approved.json"), JSON.stringify(feeTooLowButForcedApproved, null, 2));

  const recipientSwap = clone(approved);
  recipientSwap.recipientField = "999999999999";
  fs.writeFileSync(path.join(OUT_DIR, "recipient_swap.json"), JSON.stringify(recipientSwap, null, 2));

  console.log(`wrote inputs to ${OUT_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
