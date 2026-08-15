import hashlib
import os
import unittest
from pathlib import Path

import cuda_binding_merkle_v2 as binding
import cuda_fp16_zk_rs_interleaved_k128_prototype as core


def digest(role, payload):
    frame = b"BLBIND02" + (2).to_bytes(2, "big") + role.to_bytes(2, "big") + len(payload).to_bytes(8, "big") + payload
    return b"".join(
        hashlib.sha3_512(domain + frame).digest()
        for domain in (binding.LEFT_DOMAIN, binding.RIGHT_DOMAIN)
    )


def reference_root(rows, boundary, kind):
    leaf_count = len(rows)
    leaf_bytes = len(rows[0])
    frame = (
        binding.LEAF_FRAME + boundary.to_bytes(8, "big") + kind.to_bytes(8, "big")
        + (leaf_count * leaf_bytes).to_bytes(8, "big") + leaf_bytes.to_bytes(8, "big")
    )
    current = [digest(0x0101, i.to_bytes(8, "big") + frame + row) for i, row in enumerate(rows)]
    level = 1
    while len(current) > 1:
        current = [
            digest(0x0102, level.to_bytes(4, "big") + i.to_bytes(8, "big") + current[2*i] + current[2*i+1])
            for i in range(len(current) // 2)
        ]
        level += 1
    return digest(0x0103, leaf_count.to_bytes(8, "big") + (leaf_count.bit_length()-1).to_bytes(4, "big") + current[0])


class BindingMerkleV2CudaTest(unittest.TestCase):
    def test_incremental_root_matches_hand_computed_reference(self):
        module = Path(os.environ["BL_BINDING_MERKLE_TEST_CUBIN"])
        runtime = core.DriverRuntime(module.read_bytes())
        core.bind_driver(runtime)
        allocator = core.Allocator(runtime)
        try:
            functions = binding.functions(core, runtime)
            left = bytes((row * 17 + column * 3) & 0xFF for row in range(8) for column in range(64))
            right = bytes((row * 29 + column * 5 + 1) & 0xFF for row in range(8) for column in range(64))
            commitment = binding.IncrementalSourceCommitmentV2(core, runtime, allocator, functions, 8, 128, 3, 32)
            for payload in (left, right):
                buffer = core.upload(runtime, allocator, payload, "upload_binding_test_slice")
                commitment.absorb(buffer, 64)
                allocator.free(buffer)
            tree = commitment.finish()
            rows = [left[i*64:(i+1)*64] + right[i*64:(i+1)*64] for i in range(8)]
            self.assertEqual(tree.root, reference_root(rows, 3, 32))
            for level in tree.levels:
                allocator.free(level)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
