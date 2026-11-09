"use strict";

const fs = require("fs");
const path = require("path");
const circomlibjs = require("../../zk/node_modules/circomlibjs");

const OUT_DIR = path.join(__dirname, "..", "inputs-v2");
const DEPTH = 10;
const LEAF_COUNT = 1 << DEPTH;
const FIELD_MODULUS = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

function asBigInt(value) {
  return BigInt(value);
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function bitAt(value, bit) {
  return ((BigInt(value) >> BigInt(bit)) & 1n).toString();
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;
  const hash = (...values) => F.toString(poseidon(values.map(asBigInt)));

  function zeroLeaves(defaultLeaf) {
    return Array.from({ length: LEAF_COUNT }, (_, i) => defaultLeaf(i));
  }

  function buildTree(entries, defaultLeaf = () => "0") {
    let leaves = zeroLeaves(defaultLeaf);
    for (const [idx, leaf] of Object.entries(entries)) {
      leaves[Number(idx)] = leaf;
    }
    const levels = [leaves];
    for (let d = 0; d < DEPTH; d += 1) {
      const prev = levels[d];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        next.push(hash(prev[i], prev[i + 1]));
      }
      levels.push(next);
    }
    return levels;
  }

  function root(levels) {
    return levels[DEPTH][0];
  }

  function pathFor(levels, index) {
    const pathElements = [];
    const pathIndices = [];
    let idx = index;
    for (let d = 0; d < DEPTH; d += 1) {
      const sibling = idx ^ 1;
      pathElements.push(levels[d][sibling]);
      pathIndices.push((idx & 1).toString());
      idx >>= 1;
    }
    return { pathElements, pathIndices };
  }

  const emptyNullifierLeaf = (index) => hash("0", "0", "0", index.toString());

  const base = {
    rawClaimHash: "1001001001001",
    oracleSignerRoot: "424242424242",
    rulesetRoot: "900100200300",
    verifierKeyId: "2",
    memberKey: "111111111111",
    providerKey: "222222222222",
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
    noProgramIntegrityHold: "1",
    serviceDate: "20260601",
    procedureCode: "99213",
    totalChargeCents: "12000",
    lineChargeCents: "12000",
    feeEffectiveFrom: "20260101",
    feeEffectiveUntil: "20261231",
    feeAllowedAmountCents: "12000",
    addressBookVersion: "1",
    recipientField: "515151515151"
  };

  function firstFailureCode(v) {
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
      BigInt(v.lineChargeCents) <= BigInt(v.feeAllowedAmountCents) ? 1n : 0n,
      1n,
      BigInt(v.noProgramIntegrityHold)
    ];
    const codes = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 81n, 82n, 9n, 10n];
    for (let i = 0; i < gates.length; i += 1) {
      if (gates[i] === 0n) return codes[i].toString();
    }
    return "0";
  }

  function claimSourceLeafFor(v) {
    return hash(
      v.rawClaimHash,
      v.memberKey,
      v.providerKey,
      v.memberIdPresent,
      v.providerNpiPresent,
      v.serviceLinesPresent,
      v.diagnosisPresent,
      v.totalChargeCents,
      v.lineChargeCents,
      v.serviceDate,
      v.procedureCode
    );
  }

  function addClaimSourceRoot(v) {
    const claimSourceLeaf = claimSourceLeafFor(v);
    const claimSourceIndex = 5;
    const claimSourceTree = buildTree({ [claimSourceIndex]: claimSourceLeaf });
    v.claimSourceRoot = root(claimSourceTree);
    const claimSourcePath = pathFor(claimSourceTree, claimSourceIndex);
    v.claimSourcePathElements = claimSourcePath.pathElements;
    v.claimSourcePathIndices = claimSourcePath.pathIndices;
  }

  function addGovernedRoots(v) {
    const oracleLeaf = hash(
      v.memberKey,
      v.providerKey,
      v.serviceDate,
      v.eligibilityActive,
      v.providerEnrolled,
      v.providerNotSuspended,
      v.notDeceased,
      v.priorAuthValid,
      v.oracleSignerRoot
    );
    const oracleIndex = 7;
    const oracleTree = buildTree({ [oracleIndex]: oracleLeaf });
    v.oracleFactsRoot = root(oracleTree);
    const oraclePath = pathFor(oracleTree, oracleIndex);
    v.oraclePathElements = oraclePath.pathElements;
    v.oraclePathIndices = oraclePath.pathIndices;

    const feeLeaf = hash(
      v.procedureCode,
      v.feeEffectiveFrom,
      v.feeEffectiveUntil,
      v.feeAllowedAmountCents,
      v.priorAuthRequired,
      v.rulesetRoot,
      v.oracleSignerRoot
    );
    const feeIndex = 11;
    const feeTree = buildTree({ [feeIndex]: feeLeaf });
    v.feeScheduleRoot = root(feeTree);
    const feePath = pathFor(feeTree, feeIndex);
    v.feePathElements = feePath.pathElements;
    v.feePathIndices = feePath.pathIndices;

    const addressLeaf = hash(v.providerKey, v.recipientField, v.addressBookVersion);
    const addressIndex = 13;
    const addressTree = buildTree({ [addressIndex]: addressLeaf });
    v.addressBookRoot = root(addressTree);
    const addressPath = pathFor(addressTree, addressIndex);
    v.addressPathElements = addressPath.pathElements;
    v.addressPathIndices = addressPath.pathIndices;
  }

  function addNullifierTransition(v) {
    const claimSourceLeaf = claimSourceLeafFor(v);
    const nullifier = hash(claimSourceLeaf, v.memberKey, v.providerKey, v.serviceDate, v.procedureCode);
    const insertIndex = Number(BigInt(nullifier) & BigInt(LEAF_COUNT - 1));
    const predecessorIndex = (insertIndex + 1) % LEAF_COUNT;
    const successorIndex = (insertIndex + 2) % LEAF_COUNT;
    const predecessorNullifier = "1";
    const successorNullifier = (FIELD_MODULUS - 2n).toString();

    const oldPredLeaf = hash(predecessorNullifier, successorNullifier, successorIndex.toString(), predecessorIndex.toString());
    const beforeTree = buildTree({ [predecessorIndex]: oldPredLeaf }, emptyNullifierLeaf);
    v.nullifierRootBefore = root(beforeTree);
    const predecessorPath = pathFor(beforeTree, predecessorIndex);
    v.predecessorPathElements = predecessorPath.pathElements;
    v.predecessorPathIndices = predecessorPath.pathIndices;

    const updatedPredLeaf = hash(predecessorNullifier, nullifier, insertIndex.toString(), predecessorIndex.toString());
    const afterPredTree = buildTree({ [predecessorIndex]: updatedPredLeaf }, emptyNullifierLeaf);
    const insertPath = pathFor(afterPredTree, insertIndex);
    v.insertPathElements = insertPath.pathElements;
    v.insertPathIndices = insertPath.pathIndices;

    const insertedLeaf = hash(nullifier, successorNullifier, successorIndex.toString(), insertIndex.toString());
    const finalTree = buildTree({
      [predecessorIndex]: updatedPredLeaf,
      [insertIndex]: insertedLeaf
    }, emptyNullifierLeaf);

    v.nullifierRootAfter = root(finalTree);
    v.predecessorNullifier = predecessorNullifier;
    v.successorNullifier = successorNullifier;
    v.predecessorIndex = predecessorIndex.toString();
    v.successorIndex = successorIndex.toString();
    v._nullifier = nullifier;
    v._insertIndex = insertIndex.toString();
  }

  function recomputeDerived(v, force = {}) {
    const failureCode = force.failureCode ?? firstFailureCode(v);
    const decision = force.decision ?? (failureCode === "0" ? "1" : "0");
    const paymentAmountCents = force.paymentAmountCents ?? (decision === "1" ? v.feeAllowedAmountCents : "0");
    v.decision = decision;
    v.failureCode = failureCode;
    v.paymentAmountCents = paymentAmountCents;

    const claimSourceLeaf = claimSourceLeafFor(v);
    const nullifier = hash(claimSourceLeaf, v.memberKey, v.providerKey, v.serviceDate, v.procedureCode);
    v._nullifier = nullifier;

    v.claimRoot = hash(claimSourceLeaf);
    v.resultRoot = hash(
      v.decision,
      v.failureCode,
      v.paymentAmountCents,
      v.claimSourceRoot,
      v.oracleFactsRoot,
      v.feeScheduleRoot,
      v.addressBookRoot,
      v.rulesetRoot,
      nullifier
    );
    const paymentLeaf = hash(v.providerKey, v.recipientField, v.paymentAmountCents, v.resultRoot);
    v.paymentRoot = v.decision === "1" ? hash(paymentLeaf) : "0";
    v.combinedCommitment = hash(
      v.claimRoot,
      v.resultRoot,
      v.paymentRoot,
      v.nullifierRootBefore,
      v.nullifierRootAfter,
      v.claimSourceRoot,
      v.oracleFactsRoot,
      v.oracleSignerRoot,
      v.feeScheduleRoot,
      v.addressBookRoot,
      v.rulesetRoot,
      v.verifierKeyId,
      v.decision,
      v.paymentAmountCents
    );
  }

  function buildValid(overrides = {}, force = {}) {
    const v = { ...base, ...overrides };
    addClaimSourceRoot(v);
    addGovernedRoots(v);
    addNullifierTransition(v);
    recomputeDerived(v, force);
    return v;
  }

  function write(name, input) {
    const cleaned = clone(input);
    delete cleaned._nullifier;
    delete cleaned._insertIndex;
    fs.writeFileSync(path.join(OUT_DIR, `${name}.json`), JSON.stringify(cleaned, null, 2));
  }

  const approved = buildValid();
  write("approved", approved);

  const ineligibleDenied = buildValid({ eligibilityActive: "0" });
  write("ineligible_denied", ineligibleDenied);

  const fabricatedOracleFacts = clone(ineligibleDenied);
  fabricatedOracleFacts.eligibilityActive = "1";
  recomputeDerived(fabricatedOracleFacts, { decision: "1", failureCode: "0", paymentAmountCents: fabricatedOracleFacts.feeAllowedAmountCents });
  write("fabricated_oracle_facts", fabricatedOracleFacts);

  const fakeFeeCeiling = clone(approved);
  fakeFeeCeiling.totalChargeCents = "50000";
  fakeFeeCeiling.lineChargeCents = "50000";
  fakeFeeCeiling.feeAllowedAmountCents = "50000";
  recomputeDerived(fakeFeeCeiling, { decision: "1", failureCode: "0", paymentAmountCents: "50000" });
  write("fake_fee_ceiling", fakeFeeCeiling);

  const rawHashDoublePay = clone(approved);
  rawHashDoublePay.rawClaimHash = "999999000001";
  recomputeDerived(rawHashDoublePay, { decision: "1", failureCode: "0", paymentAmountCents: rawHashDoublePay.feeAllowedAmountCents });
  write("raw_hash_double_pay_attempt", rawHashDoublePay);

  const memberCollision = clone(approved);
  memberCollision.memberKey = "333333333333";
  recomputeDerived(memberCollision, { decision: "1", failureCode: "0", paymentAmountCents: memberCollision.feeAllowedAmountCents });
  write("member_swap_collision_attempt", memberCollision);

  const procedureSubstitution = clone(approved);
  procedureSubstitution.procedureCode = "99999";
  procedureSubstitution.feeAllowedAmountCents = "50000";
  recomputeDerived(procedureSubstitution, { decision: "1", failureCode: "0", paymentAmountCents: "50000" });
  write("procedure_substitution_attempt", procedureSubstitution);

  const recipientRedirect = clone(approved);
  recipientRedirect.recipientField = "999999999999";
  recomputeDerived(recipientRedirect);
  write("recipient_redirect", recipientRedirect);

  const authRequiredDenied = buildValid({ priorAuthRequired: "1", priorAuthValid: "0" });
  const priorAuthBypass = clone(authRequiredDenied);
  priorAuthBypass.priorAuthRequired = "0";
  priorAuthBypass.priorAuthValid = "0";
  recomputeDerived(priorAuthBypass, { decision: "1", failureCode: "0", paymentAmountCents: priorAuthBypass.feeAllowedAmountCents });
  write("prior_auth_bypass", priorAuthBypass);

  const duplicateReplay = clone(approved);
  duplicateReplay.nullifierRootBefore = approved.nullifierRootAfter;
  recomputeDerived(duplicateReplay);
  write("duplicate_replay_forged_nonmembership", duplicateReplay);

  const overwideAmount = buildValid({
    totalChargeCents: "1099511627776",
    lineChargeCents: "1099511627776",
    feeAllowedAmountCents: "1099511627776"
  }, { decision: "1", failureCode: "0", paymentAmountCents: "1099511627776" });
  write("overwide_amount", overwideAmount);

  console.log(`wrote v2 inputs to ${OUT_DIR}`);
  console.log(`approved nullifier low ${DEPTH} bits index: ${approved._insertIndex}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
