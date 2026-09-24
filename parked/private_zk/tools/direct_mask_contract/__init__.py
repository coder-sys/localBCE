"""Nonactivating direct-mask degree-three computation contract.

The calculator exports are lazy so ``python -m parked.private_zk.tools.direct_mask_contract.calculator``
does not import the module once through this package and then execute it a second time.
"""

from importlib import import_module


__all__ = [
    "ContractError",
    "admission_ledger",
    "bavc_leaf_index",
    "bavc_opening_gate",
    "bavc_opening_node_count",
    "calculate_report",
    "counter_contract",
    "decode_all_chall_3",
    "exact_good_count_enumeration",
    "load_manifest",
    "p_good_exact_expression",
    "proof_body_allocation",
    "qrom_bound",
    "retry_abort_ledger",
    "resource_ledger",
    "security_accounting",
    "source_reissue_bound",
    "privacy_switch_bound",
    "uncapped_hash_bounds",
    "wire_contract_report",
]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(".calculator", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value
