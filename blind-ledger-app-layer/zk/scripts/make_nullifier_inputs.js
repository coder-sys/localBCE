const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");

const DEPTH = 32;
const MAX_U32 = 4294967295n;

function toBits(index) {
  const bits = [];
  let value = BigInt(index);
  for (let i = 0; i < DEPTH; i++) {
    bits.push(Number((value >> BigInt(i)) & 1n));
  }
  return bits;
}

function fieldString(poseidon, value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  return poseidon.F.toString(value);
}

function poseidonField(poseidon, inputs) {
  return poseidon.F.toObject(poseidon(inputs.map(BigInt)));
}

function leafHash(poseidon, leaf) {
  return poseidonField(poseidon, [leaf.leafValue, leaf.nextValue, leaf.nextIndex, leaf.leafIndex]);
}

function nodeHash(poseidon, left, right) {
  return poseidonField(poseidon, [left, right]);
}

function defaultHashes(poseidon) {
  const defaults = [0n];
  for (let i = 0; i < DEPTH; i++) {
    defaults.push(nodeHash(poseidon, defaults[i], defaults[i]));
  }
  return defaults;
}

function buildTree(poseidon, leaves) {
  const defaults = defaultHashes(poseidon);
  const levels = [];
  levels[0] = new Map();
  for (const leaf of leaves) {
    levels[0].set(Number(leaf.leafIndex), leafHash(poseidon, leaf));
  }

  for (let level = 0; level < DEPTH; level++) {
    const next = new Map();
    const parents = new Set();
    for (const index of levels[level].keys()) {
      parents.add(Math.floor(index / 2));
    }
    for (const parent of parents) {
      const leftIndex = parent * 2;
      const rightIndex = leftIndex + 1;
      const left = levels[level].get(leftIndex) ?? defaults[level];
      const right = levels[level].get(rightIndex) ?? defaults[level];
      next.set(parent, nodeHash(poseidon, left, right));
    }
    levels[level + 1] = next;
  }

  const root = levels[DEPTH].get(0) ?? defaults[DEPTH];
  return { root, levels, defaults };
}

function pathFor(tree, leafIndex) {
  const pathElements = [];
  const pathIndices = toBits(leafIndex);
  let index = Number(leafIndex);
  for (let level = 0; level < DEPTH; level++) {
    const siblingIndex = index ^ 1;
    pathElements.push(tree.levels[level].get(siblingIndex) ?? tree.defaults[level]);
    index = Math.floor(index / 2);
  }
  return { pathElements, pathIndices };
}

function asInput(poseidon, tree, witness) {
  const path = pathFor(tree, witness.leafIndex);
  return {
    root: fieldString(poseidon, tree.root),
    nullifier: witness.nullifier.toString(),
    leafIndex: witness.leafIndex.toString(),
    leafValue: witness.leafValue.toString(),
    nextValue: witness.nextValue.toString(),
    nextIndex: witness.nextIndex.toString(),
    pathElements: path.pathElements.map((value) => fieldString(poseidon, value)),
    pathIndices: path.pathIndices.map(String)
  };
}

async function main() {
  const caseName = process.argv[2] || "fresh";
  const outPath = process.argv[3] || path.join(__dirname, "..", "inputs", `nullifier_${caseName}.json`);
  const poseidon = await buildPoseidon();

  const leaves = [
    { leafIndex: 0n, leafValue: 0n, nextValue: 10n, nextIndex: 1n },
    { leafIndex: 1n, leafValue: 10n, nextValue: 30n, nextIndex: 2n },
    { leafIndex: 2n, leafValue: 30n, nextValue: MAX_U32, nextIndex: 0n }
  ];
  const tree = buildTree(poseidon, leaves);

  const cases = {
    fresh: {
      description: "nullifier 20 is between predecessor 10 and successor 30",
      witness: { nullifier: 20n, leafIndex: 1n, leafValue: 10n, nextValue: 30n, nextIndex: 2n },
      expected: "accept"
    },
    duplicate: {
      description: "nullifier 10 is already present; predecessor interval 0..10 is not open",
      witness: { nullifier: 10n, leafIndex: 0n, leafValue: 0n, nextValue: 10n, nextIndex: 1n },
      expected: "reject"
    },
    tampered: {
      description: "nullifier 10 tries a forged wider predecessor interval 0..30 at an existing leaf position",
      witness: { nullifier: 10n, leafIndex: 0n, leafValue: 0n, nextValue: 30n, nextIndex: 2n },
      expected: "reject"
    }
  };

  const selected = cases[caseName];
  if (!selected) {
    throw new Error(`unknown case ${caseName}`);
  }

  const input = asInput(poseidon, tree, selected.witness);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(input, null, 2)}\n`);
  console.log(JSON.stringify({
    case: caseName,
    expected: selected.expected,
    description: selected.description,
    outPath,
    root: input.root,
    nullifier: input.nullifier,
    leafIndex: input.leafIndex,
    leafValue: input.leafValue,
    nextValue: input.nextValue,
    nextIndex: input.nextIndex
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
