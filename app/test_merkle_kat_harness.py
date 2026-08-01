import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.batch.merkle import MerkleTree


def _field_to_hex32(value: int) -> str:
    return f"{value:064x}"


def generate_kat_test_cases(num_trees=100, depth=20):
    """Generate KAT test cases: leaf, index, siblings, root."""
    random.seed(42)
    test_cases = []
    for i in range(num_trees):
        num_leaves = random.randint(10, min(1024, 2**depth))
        leaves = [_field_to_hex32(random.randint(1, 2**251)) for _ in range(num_leaves)]
        tree = MerkleTree(leaves=leaves, depth=depth)
        leaf_index = random.randint(0, len(leaves) - 1)
        proof = tree.prove(leaf_index)

        test_cases.append({
            "tree_id": i,
            "leaf": proof.leaf,
            "index": leaf_index,
            "siblings": proof.siblings,
            "expected_root": proof.root,
        })
    return test_cases


if __name__ == "__main__":
    cases = generate_kat_test_cases(100, 20)
    output_dir = Path("test_data")
    output_dir.mkdir(exist_ok=True)
    with (output_dir / "merkle_kat_100_trees.jsonl").open("w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case) + "\n")
    print(f"Generated {len(cases)} KAT test cases")
    print("First 5 cases:")
    for case in cases[:5]:
        print(json.dumps(case, indent=2))
