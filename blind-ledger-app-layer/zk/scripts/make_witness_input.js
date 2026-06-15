const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");

const CASES = {
  approved: {
    memberId: 123456789,
    providerNpi: 1999999987,
    eligibilityActive: 1,
    providerEnrolled: 1,
    serviceLineCount: 1,
    diagnosisCount: 1,
    priorAuthOk: 1,
    chargeCents: 12500,
    maxChargeCents: 500000,
    duplicateFlag: 0,
    programIntegrityHold: 0,
    claimNonce: 42,
    decision: 1,
    failureCode: 0
  },
  duplicateDenied: {
    memberId: 123456789,
    providerNpi: 1999999987,
    eligibilityActive: 1,
    providerEnrolled: 1,
    serviceLineCount: 1,
    diagnosisCount: 1,
    priorAuthOk: 1,
    chargeCents: 12500,
    maxChargeCents: 500000,
    duplicateFlag: 1,
    programIntegrityHold: 0,
    claimNonce: 43,
    decision: 0,
    failureCode: 9
  },
  ineligibleDenied: {
    memberId: 123456789,
    providerNpi: 1999999987,
    eligibilityActive: 0,
    providerEnrolled: 1,
    serviceLineCount: 1,
    diagnosisCount: 1,
    priorAuthOk: 1,
    chargeCents: 12500,
    maxChargeCents: 500000,
    duplicateFlag: 0,
    programIntegrityHold: 0,
    claimNonce: 44,
    decision: 0,
    failureCode: 2
  }
};

function asFieldString(poseidon, value) {
  return poseidon.F.toString(value);
}

async function main() {
  const name = process.argv[2] || "approved";
  const outPath = process.argv[3] || path.join(__dirname, "..", "inputs", `${name}.json`);
  const data = CASES[name];
  if (!data) {
    throw new Error(`unknown case ${name}`);
  }

  const poseidon = await buildPoseidon();
  const commitmentInputs = [
    data.memberId,
    data.providerNpi,
    data.eligibilityActive,
    data.providerEnrolled,
    data.serviceLineCount,
    data.diagnosisCount,
    data.priorAuthOk,
    data.chargeCents,
    data.maxChargeCents,
    data.duplicateFlag,
    data.programIntegrityHold
  ].map(BigInt);
  const nullifierInputs = [data.memberId, data.claimNonce].map(BigInt);
  const claimCommitment = asFieldString(poseidon, poseidon(commitmentInputs));
  const nullifier = asFieldString(poseidon, poseidon(nullifierInputs));
  const input = {
    ...Object.fromEntries(Object.entries(data).map(([key, value]) => [key, String(value)])),
    claimCommitment,
    nullifier
  };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(input, null, 2)}\n`);
  console.log(JSON.stringify({ case: name, outPath, claimCommitment, nullifier, decision: data.decision, failureCode: data.failureCode }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
