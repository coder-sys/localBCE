from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List

from app.batch.poseidon import FIELD_MODULUS, poseidon_hash, poseidon_many


DEPTH = 32
MAX_NULLIFIER = FIELD_MODULUS - 1
ROOT = Path(__file__).resolve().parents[2]
ZK_DIR = ROOT / "zk"
NODE_DIR = ROOT / "toolchains" / "node" / "node-v24.16.0-win-x64"
NODE_EXE = NODE_DIR / "node.exe"
SNARKJS = ZK_DIR / "node_modules" / ".bin" / "snarkjs.cmd"
WITNESS_JS = ZK_DIR / "build_nullifier" / "nullifier_nonmembership_js" / "generate_witness.js"
WASM = ZK_DIR / "build_nullifier" / "nullifier_nonmembership_js" / "nullifier_nonmembership.wasm"
R1CS = ZK_DIR / "build_nullifier" / "nullifier_nonmembership.r1cs"
ZKEY = ZK_DIR / "keys_nullifier" / "nullifier_nonmembership_final.zkey"
VKEY = ZK_DIR / "keys_nullifier" / "nullifier_nonmembership_verification_key.json"
RUNTIME_DIR = ROOT / "app" / "batch" / "nullifier_runtime"


class DuplicateNullifierError(ValueError):
    pass


def field_to_hex(value: int) -> str:
    return f"{int(value):064x}"


@dataclass(frozen=True)
class IndexedLeaf:
    index: int
    value: int
    next_value: int
    next_index: int

    @property
    def hash(self) -> int:
        return _indexed_leaf_hash(self.value, self.next_value, self.next_index, self.index)


_PAIR_HASH_CACHE: Dict[tuple[int, int], int] = {}
_LEAF_HASH_CACHE: Dict[tuple[int, int, int, int], int] = {}


def _indexed_leaf_hash(value: int, next_value: int, next_index: int, index: int) -> int:
    key = (int(value), int(next_value), int(next_index), int(index))
    cached = _LEAF_HASH_CACHE.get(key)
    if cached is not None:
        return cached
    hashed = poseidon_hash(key)
    _LEAF_HASH_CACHE[key] = hashed
    return hashed


def _pair_hashes(rows: List[List[int]]) -> List[int]:
    out: List[int | None] = [None] * len(rows)
    missing_keys: List[tuple[int, int]] = []
    missing_rows: List[List[int]] = []
    for index, row in enumerate(rows):
        key = (int(row[0]), int(row[1]))
        cached = _PAIR_HASH_CACHE.get(key)
        if cached is None:
            missing_keys.append(key)
            missing_rows.append([key[0], key[1]])
        else:
            out[index] = cached
    if missing_rows:
        hashed = poseidon_many(missing_rows)
        for key, value in zip(missing_keys, hashed):
            _PAIR_HASH_CACHE[key] = value
    for index, row in enumerate(rows):
        if out[index] is None:
            key = (int(row[0]), int(row[1]))
            out[index] = _PAIR_HASH_CACHE[key]
    return [int(value) for value in out]


@dataclass(frozen=True)
class NonMembershipWitness:
    root: int
    nullifier: int
    leafIndex: int
    leafValue: int
    nextValue: int
    nextIndex: int
    pathElements: List[int]
    pathIndices: List[int]

    def to_circuit_input(self) -> Dict[str, object]:
        data = asdict(self)
        return {
            key: [str(item) for item in value] if isinstance(value, list) else str(value)
            for key, value in data.items()
        }


@dataclass(frozen=True)
class NullifierProofResult:
    case_name: str
    accepted: bool
    proof_path: str
    public_path: str
    proof_size_bytes: int
    witness_time_ms: int
    prove_time_ms: int
    verify_time_ms: int
    public_values: List[str]


@lru_cache(maxsize=None)
def _zero_hashes(depth: int = DEPTH) -> tuple[int, ...]:
    zeros = [0]
    current = 0
    for _ in range(depth):
        current = _pair_hashes([[current, current]])[0]
        zeros.append(current)
    return tuple(zeros)


class IndexedNullifierTree:
    """Sparse indexed Merkle tree matching nullifier_nonmembership.circom.

    V2 uses full Poseidon field-element nullifiers. The maximum field element is
    reserved as the ordered-tree successor sentinel.
    """

    def __init__(self, leaves: Iterable[int] | None = None):
        self._nodes: Dict[int, IndexedLeaf] = {
            0: IndexedLeaf(0, 0, MAX_NULLIFIER, 1),
            1: IndexedLeaf(1, MAX_NULLIFIER, MAX_NULLIFIER, 1),
        }
        self._value_to_index: Dict[int, int] = {0: 0, MAX_NULLIFIER: 1}
        self._next_index = 2
        self._zeros = _zero_hashes()
        for value in leaves or []:
            self.insert(value)

    def clone(self) -> "IndexedNullifierTree":
        cloned = IndexedNullifierTree()
        cloned._nodes = dict(self._nodes)
        cloned._value_to_index = dict(self._value_to_index)
        cloned._next_index = self._next_index
        cloned._zeros = self._zeros
        return cloned

    @property
    def root(self) -> int:
        return self._root_and_path(0)[0]

    @property
    def root_hex(self) -> str:
        return field_to_hex(self.root)

    def contains(self, value: int) -> bool:
        return int(value) in self._value_to_index

    def _validate_value(self, value: int) -> int:
        value = int(value)
        if value <= 0 or value >= MAX_NULLIFIER:
            raise ValueError("nullifier must be in the full-field non-sentinel range")
        return value

    def _sorted_values(self) -> List[int]:
        return sorted(self._value_to_index)

    def _predecessor_successor(self, value: int) -> tuple[IndexedLeaf, IndexedLeaf]:
        values = self._sorted_values()
        pred_value = values[0]
        succ_value = values[-1]
        for current in values:
            if current < value:
                pred_value = current
            elif current > value:
                succ_value = current
                break
        return self._nodes[self._value_to_index[pred_value]], self._nodes[self._value_to_index[succ_value]]

    def _root_and_path(self, target_index: int) -> tuple[int, List[int], List[int]]:
        nodes = {index: leaf.hash for index, leaf in self._nodes.items()}
        path_elements: List[int] = []
        path_indices: List[int] = []
        cursor = int(target_index)

        for level in range(DEPTH):
            path_elements.append(nodes.get(cursor ^ 1, self._zeros[level]))
            path_indices.append(cursor & 1)
            parent_rows = []
            parent_indices = []
            for parent in sorted({index // 2 for index in nodes}):
                left = nodes.get(parent * 2, self._zeros[level])
                right = nodes.get(parent * 2 + 1, self._zeros[level])
                parent_indices.append(parent)
                parent_rows.append([left, right])
            nodes = dict(zip(parent_indices, _pair_hashes(parent_rows))) if parent_rows else {}
            cursor //= 2

        return nodes.get(0, self._zeros[DEPTH]), path_elements, path_indices

    def prove_nonmembership(self, value: int) -> NonMembershipWitness:
        value = self._validate_value(value)
        if self.contains(value):
            raise DuplicateNullifierError(f"nullifier already present: {value}")
        predecessor, successor = self._predecessor_successor(value)
        root, path_elements, path_indices = self._root_and_path(predecessor.index)
        return NonMembershipWitness(
            root=root,
            nullifier=value,
            leafIndex=predecessor.index,
            leafValue=predecessor.value,
            nextValue=successor.value,
            nextIndex=successor.index,
            pathElements=path_elements,
            pathIndices=path_indices,
        )

    def duplicate_rejection_witness(self, value: int) -> NonMembershipWitness:
        value = self._validate_value(value)
        if not self.contains(value):
            raise ValueError("duplicate rejection witness requires a present nullifier")
        values = self._sorted_values()
        pos = values.index(value)
        predecessor_value = values[max(pos - 1, 0)]
        predecessor = self._nodes[self._value_to_index[predecessor_value]]
        root, path_elements, path_indices = self._root_and_path(predecessor.index)
        return NonMembershipWitness(
            root=root,
            nullifier=value,
            leafIndex=predecessor.index,
            leafValue=predecessor.value,
            nextValue=predecessor.next_value,
            nextIndex=predecessor.next_index,
            pathElements=path_elements,
            pathIndices=path_indices,
        )

    def insert(self, value: int) -> None:
        value = self._validate_value(value)
        if self.contains(value):
            raise DuplicateNullifierError(f"nullifier already present: {value}")
        predecessor, successor = self._predecessor_successor(value)
        new_index = self._next_index
        self._next_index += 1
        self._nodes[predecessor.index] = IndexedLeaf(predecessor.index, predecessor.value, value, new_index)
        self._nodes[new_index] = IndexedLeaf(new_index, value, successor.value, successor.index)
        self._value_to_index[value] = new_index


class NullifierProofRunner:
    def __init__(self, runtime_dir: Path = RUNTIME_DIR):
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

    def _env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{NODE_DIR};{env.get('PATH', '')}"
        return env

    def _run(self, args: List[str], *, cwd: Path | None = None) -> tuple[int, str, str, int]:
        start = time.perf_counter()
        proc = subprocess.run(args, cwd=cwd or ROOT, text=True, capture_output=True, env=self._env())
        elapsed = int((time.perf_counter() - start) * 1000)
        return proc.returncode, proc.stdout, proc.stderr, elapsed

    def prove_and_verify(self, witness: NonMembershipWitness, case_name: str) -> NullifierProofResult:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case_name)
        input_path = self.runtime_dir / f"{safe}.input.json"
        witness_path = self.runtime_dir / f"{safe}.wtns"
        proof_path = self.runtime_dir / f"{safe}.proof.json"
        public_path = self.runtime_dir / f"{safe}.public.json"
        input_path.write_text(json.dumps(witness.to_circuit_input(), indent=2), encoding="utf-8")

        code, stdout, stderr, witness_ms = self._run(
            [str(NODE_EXE), str(WITNESS_JS), str(WASM), str(input_path), str(witness_path)]
        )
        if code != 0:
            raise ValueError(f"witness generation failed for {case_name}: {stdout}{stderr}")

        code, stdout, stderr, _ = self._run(
            [str(SNARKJS), "wtns", "check", str(R1CS), str(witness_path)]
        )
        if code != 0:
            raise ValueError(f"witness check failed for {case_name}: {stdout}{stderr}")

        code, stdout, stderr, prove_ms = self._run(
            [str(SNARKJS), "groth16", "prove", str(ZKEY), str(witness_path), str(proof_path), str(public_path)]
        )
        if code != 0:
            raise ValueError(f"proof generation failed for {case_name}: {stdout}{stderr}")

        code, stdout, stderr, verify_ms = self._run(
            [str(SNARKJS), "groth16", "verify", str(VKEY), str(public_path), str(proof_path)]
        )
        accepted = code == 0 and "OK!" in (stdout + stderr)
        return NullifierProofResult(
            case_name=case_name,
            accepted=accepted,
            proof_path=str(proof_path),
            public_path=str(public_path),
            proof_size_bytes=proof_path.stat().st_size,
            witness_time_ms=witness_ms,
            prove_time_ms=prove_ms,
            verify_time_ms=verify_ms,
            public_values=json.loads(public_path.read_text(encoding="utf-8")),
        )

    def expect_reject(self, witness: NonMembershipWitness, case_name: str) -> str:
        try:
            result = self.prove_and_verify(witness, case_name)
        except Exception as exc:
            return str(exc)
        if result.accepted:
            raise AssertionError(f"{case_name} unexpectedly generated and verified")
        return "proof did not verify"
