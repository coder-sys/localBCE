const fs = require("fs");
const path = require("path");

const r1csPath = process.argv[2] || path.join(__dirname, "..", "build", "claim_adjudication_core.r1cs.json");

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (!fs.existsSync(r1csPath)) {
  fail(`missing r1cs json: ${r1csPath}`);
}

const r1cs = JSON.parse(fs.readFileSync(r1csPath, "utf8"));
const signals = r1cs.nVars ?? r1cs.nSignals ?? 0;
const constraints = r1cs.constraints?.length ?? 0;
const publicInputs = r1cs.nPubInputs ?? 0;
const publicOutputs = r1cs.nOutputs ?? 0;
const privateInputs = r1cs.nPrvInputs ?? 0;

const findings = [];
if (constraints <= 0) findings.push("NO_CONSTRAINTS");
if (publicInputs !== 4) findings.push(`UNEXPECTED_PUBLIC_INPUT_COUNT_${publicInputs}`);
if (privateInputs < 12) findings.push(`UNEXPECTED_PRIVATE_INPUT_COUNT_${privateInputs}`);
if (constraints < signals / 4) findings.push("LOW_CONSTRAINT_TO_SIGNAL_RATIO_REVIEW_REQUIRED");

const result = {
  r1csPath,
  signals,
  constraints,
  publicInputs,
  publicOutputs,
  privateInputs,
  checks: {
    nonzeroConstraintSystem: constraints > 0,
    expectedPublicInputs: publicInputs === 4,
    expectedPrivateInputsAtLeastCircuitInputs: privateInputs >= 12,
    constraintToSignalRatioReview: constraints >= signals / 4
  },
  findings
};

console.log(JSON.stringify(result, null, 2));
if (findings.length > 0) {
  process.exit(2);
}
