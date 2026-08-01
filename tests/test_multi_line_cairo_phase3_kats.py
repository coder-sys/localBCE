from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from dataclasses import replace
from pathlib import Path

from app.batch.batch_orchestrator import BatchConfig, adjudicate_for_batch, fee_row_leaf
from app.batch.nullifier import MAX_NULLIFIER, IndexedLeaf, IndexedNullifierTree
from app.batch.stark_binding import (
    batch_output_leaf_for_claim_output,
    build_multi_line_service_line_witness,
    claim_output_for_multi_line_witness,
    multi_line_claim_payment_commitment,
    _nullifier_transition_witness_from_nonmembership,
)
from app.batch.tar_required import is_tar_required
from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.batch.stark_encoding import pack_felt_text
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.models import Patient, Provider, ServiceLine, SharedContext
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"


def _run_cairo(package_name: str, body: str, *, check: bool = True) -> str:
    with tempfile.TemporaryDirectory(prefix=f"{package_name}-") as temp:
        temp_path = Path(temp)
        (temp_path / "src").mkdir()
        (temp_path / "Scarb.toml").write_text(
            textwrap.dedent(
                f"""
                [package]
                name = "{package_name}"
                version = "0.1.0"
                edition = "2024_07"

                [cairo]
                enable-gas = false

                [dependencies]
                blind_ledger_cairo_adjudication = {{ path = "{CAIRO_PACKAGE.as_posix()}" }}

                [dev-dependencies]
                cairo_test = "2.18.0"
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (temp_path / "src" / "lib.cairo").write_text(
            textwrap.dedent(
                f"""
                use blind_ledger_cairo_adjudication::{{
                    ClaimSourceWitness, MultiLineAuthorizationWitness, MultiLineFeePolicyWitness,
                    MultiLineFeeRowWitness,
                    MultiLineServiceLineWitness, MultiLineClaimWitness, MultiLineDecisionInput, NullifierNonMembershipWitness,
                    compute_multi_line_claim_math, adjudicate_multi_line_phase3
                }};

                #[cfg(test)]
                mod tests {{
                    use super::*;

                {textwrap.indent(body, "    ")}
                }}
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(["scarb", "test"], cwd=temp_path, text=True, capture_output=True, check=check)
    return proc.stdout + proc.stderr


def _array(name: str, suffix: str, values: tuple[int, ...] | list[int]) -> list[str]:
    lines = [f"    let mut {name} = ArrayTrait::new();"]
    for value in values:
        lines.append(f"    {name}.append({int(value)}_{suffix});")
    return lines


def _path_indices(leaf_index: int, sibling_count: int) -> list[int]:
    return [(leaf_index >> level) & 1 for level in range(sibling_count)]


def _pack_optional_felt_text(value: str) -> int:
    return 0 if value == "" else pack_felt_text(value)


def _old_single_fee_payment_commitment(bundle) -> int:
    return domain_poseidon_hash(
        "payment",
        [
            901,
            int(bundle.claim.claim_source_leaf),
            int(bundle.normalized_fact_commitment),
            int(bundle.service_lines[0].fee_leaf),
            _inserted_nullifier(bundle),
            int(bundle.ruleset_root),
        ],
    )


def _inserted_nullifier(bundle) -> int:
    return (int(bundle.nullifier.inserted_nullifier_high) << 128) + int(bundle.nullifier.inserted_nullifier_low)


def _root_args(bundle, *, claim_bundle=None) -> str:
    claim_source_bundle = claim_bundle or bundle
    return (
        f"{int(bundle.ruleset_root)}_felt252, "
        f"{int(bundle.ruleset_root)}_felt252, "
        f"{int(claim_source_bundle.claim.claim_source_root)}_felt252, "
        f"{int(claim_source_bundle.claim.claim_source_root)}_felt252, "
        f"{int(bundle.oracle_facts_root)}_felt252, "
        f"{int(bundle.oracle_facts_root)}_felt252, "
        f"{int(bundle.policy_root)}_felt252, "
        f"{int(bundle.policy_root)}_felt252"
    )


def _adjudicate_call(input_var: str, bundle, *, claim_bundle=None) -> str:
    prefix = input_var.removesuffix("_input")
    return (
        f"adjudicate_multi_line_phase3("
        f"{input_var}, {prefix}_fee_policy, {prefix}_policy_rows.span(), "
        f"{prefix}_nullifier, "
        f"{_root_args(bundle, claim_bundle=claim_bundle)})"
    )


def _math_call(input_var: str, bundle) -> str:
    prefix = input_var.removesuffix("_input")
    return (
        f"compute_multi_line_claim_math("
        f"{input_var}.lines, "
        f"{int(bundle.oracle_facts_root)}_felt252, "
        f"{prefix}_policy_rows.span())"
    )


def _claim_source_literal(prefix: str, claim) -> tuple[list[str], str]:
    path = f"{prefix}_claim_path"
    statements: list[str] = []
    statements.extend(_array(path, "felt252", claim.claim_source_path_elements))
    var_name = f"{prefix}_claim_source"
    statements.extend(
        [
            f"    let {var_name} = ClaimSourceWitness {{",
            f"        claim_source_leaf: {int(claim.claim_source_leaf)}_felt252,",
            f"        claim_id: {int(claim.claim_id)}_felt252,",
            f"        member_id: {int(claim.member_id)}_felt252,",
            f"        provider_npi: {int(claim.provider_npi)}_felt252,",
            f"        service_date_day: {int(claim.service_date_day)}_u128,",
            f"        service_lines_commitment: {int(claim.service_lines_commitment)}_felt252,",
            f"        diagnosis_commitment: {int(claim.diagnosis_commitment)}_felt252,",
            f"        total_charge_cents: {int(claim.total_charge_cents)}_u128,",
            f"        source_authority_id: {int(claim.source_authority_id)}_felt252,",
            f"        payer_id: {int(claim.payer_id)}_felt252,",
            f"        attempt_version: {int(claim.attempt_version)}_u128,",
            f"        revision_kind: {int(claim.revision_kind)}_u32,",
            f"        parent_attempt_version: {int(claim.parent_attempt_version)}_u128,",
            f"        attempt_nullifier: {int(claim.attempt_nullifier)}_felt252,",
            f"        service_line_count: {int(claim.service_line_count)}_u128,",
            f"        diagnosis_count: {int(claim.diagnosis_count)}_u128,",
            f"        claim_source_leaf_index: {int(claim.claim_source_leaf_index)}_u128,",
            f"        claim_source_path_elements: {path}.span(),",
            "    };",
        ]
    )
    return statements, var_name


def _nullifier_literal(prefix: str, nullifier) -> tuple[list[str], str]:
    pred_path = f"{prefix}_null_pred_path"
    ins_path = f"{prefix}_null_ins_path"
    statements: list[str] = []
    statements.extend(_array(pred_path, "felt252", nullifier.predecessor_path_elements))
    statements.extend(_array(ins_path, "felt252", nullifier.inserted_path_elements))
    var_name = f"{prefix}_nullifier"
    statements.extend(
        [
            f"    let {var_name} = NullifierNonMembershipWitness {{",
            f"        live_root_before: {int(nullifier.live_root_before)}_felt252,",
            f"        onchain_root_before: {int(nullifier.onchain_root_before)}_felt252,",
            f"        root_after: {int(nullifier.root_after)}_felt252,",
            f"        onchain_root_after: {int(nullifier.onchain_root_after)}_felt252,",
            f"        inserted_nullifier_high: {int(nullifier.inserted_nullifier_high)}_u128,",
            f"        inserted_nullifier_low: {int(nullifier.inserted_nullifier_low)}_u128,",
            f"        predecessor_value_high: {int(nullifier.predecessor_value_high)}_u128,",
            f"        predecessor_value_low: {int(nullifier.predecessor_value_low)}_u128,",
            f"        successor_value_high: {int(nullifier.successor_value_high)}_u128,",
            f"        successor_value_low: {int(nullifier.successor_value_low)}_u128,",
            f"        predecessor_index: {int(nullifier.predecessor_index)}_u128,",
            f"        successor_index: {int(nullifier.successor_index)}_u128,",
            f"        inserted_index: {int(nullifier.inserted_index)}_u128,",
            f"        predecessor_path_elements: {pred_path}.span(),",
            f"        inserted_path_elements: {ins_path}.span(),",
            "    };",
        ]
    )
    return statements, var_name


def _bump_path(values: tuple[int, ...], delta: int) -> list[int]:
    bumped = list(values)
    if delta:
        bumped[0] = (int(bumped[0]) + delta) % FIELD_MODULUS
    return bumped


def _line_literal(
    prefix: str,
    line,
    *,
    line_charge_cents_override: int | None = None,
    units_cents_override: int | None = None,
    allowed_delta: int = 0,
    procedure_code_override: str | None = None,
    fee_leaf_override: int | None = None,
    fee_path_delta: int = 0,
    tar_required_override: int | None = None,
    policy_present_override: int | None = None,
    row_kind_override: int | None = None,
    row_procedure_code_override: int | None = None,
    row_policy_leaf_index_override: int | None = None,
    row_next_procedure_code_override: int | None = None,
    row_next_policy_leaf_index_override: int | None = None,
    policy_row_index_override: int | None = None,
    auth_override=None,
    auth_procedure_code_override: int | None = None,
    auth_line_index_override: int | None = None,
    auth_signed_delta: int = 0,
    auth_path_delta: int = 0,
) -> tuple[list[str], str]:
    _ = (
        fee_leaf_override,
        fee_path_delta,
        row_kind_override,
        row_procedure_code_override,
        row_policy_leaf_index_override,
        row_next_procedure_code_override,
        row_next_policy_leaf_index_override,
    )
    allowed_cents = int(line.allowed_cents) + allowed_delta
    line_charge_cents = (
        int(line.line_charge_cents)
        if line_charge_cents_override is None
        else int(line_charge_cents_override)
    )
    units_cents = int(line.units_cents) if units_cents_override is None else int(units_cents_override)
    procedure_code = procedure_code_override or line.procedure_code
    tar_required = int(bool(line.tar_required)) if tar_required_override is None else int(tar_required_override)
    policy_present = int(bool(line.policy_present)) if policy_present_override is None else int(policy_present_override)
    policy_row_index = int(line.policy_row_index) if policy_row_index_override is None else int(policy_row_index_override)
    statements: list[str] = []
    var_name = f"{prefix}_line"
    statements.extend(
        [
            f"    let {var_name} = MultiLineServiceLineWitness {{",
            f"        procedure_code: {pack_felt_text(procedure_code)}_felt252,",
            f"        line_charge_cents: {line_charge_cents}_u128,",
            f"        units_cents: {units_cents}_u128,",
            f"        prior_authorization: {_pack_optional_felt_text(line.prior_authorization)}_felt252,",
            f"        allowed_cents: {allowed_cents}_u128,",
            f"        tar_required: {tar_required}_u32,",
            f"        policy_present: {policy_present}_u32,",
            f"        policy_row_index: {policy_row_index}_u128,",
            f"        authorization_index: {int(line.authorization_index)}_u128,",
            "    };",
        ]
    )
    return statements, var_name


def _fee_policy_literal(prefix: str, bundle) -> tuple[list[str], str]:
    path = f"{prefix}_fee_policy_path"
    var_name = f"{prefix}_fee_policy"
    statements = _array(path, "felt252", bundle.fee_policy.fee_policy_path_elements)
    statements.extend(
        [
            f"    let {var_name} = MultiLineFeePolicyWitness {{",
            f"        fee_policy_leaf: {int(bundle.fee_policy.fee_policy_leaf)}_felt252,",
            f"        fee_policy_leaf_index: {int(bundle.fee_policy.fee_policy_leaf_index)}_u128,",
            f"        tree_depth: {int(bundle.fee_policy.tree_depth)}_u128,",
            f"        real_row_count: {int(bundle.fee_policy.real_row_count)}_u128,",
            f"        fee_policy_path_elements: {path}.span(),",
            "    };",
        ]
    )
    return statements, var_name


def _policy_rows_literal(
    prefix: str,
    bundle,
    *,
    line_options_by_index: dict[int, dict[str, object]] | None = None,
    first_line_options: dict[str, object] | None = None,
) -> tuple[list[str], str]:
    statements: list[str] = []
    row_options: dict[int, dict[str, object]] = {}
    for line_index, line in enumerate(bundle.service_lines):
        options = dict((line_options_by_index or {}).get(line_index, {}))
        if line_index == 0 and first_line_options:
            options.update(first_line_options)
        if options:
            row_options.setdefault(int(line.policy_row_index), {}).update(options)
    row_vars: list[str] = []
    for index, row in enumerate(bundle.policy_rows):
        options = row_options.get(index, {})
        path = f"{prefix}_policy_row_{index}_path"
        statements.extend(_array(path, "felt252", _bump_path(row.policy_path_elements, int(options.get("fee_path_delta", 0)))))
        var_name = f"{prefix}_policy_row_{index}"
        row_vars.append(var_name)
        requires_tar = int(bool(row.requires_tar)) if "tar_required_override" not in options else int(options["tar_required_override"])
        row_kind = int(row.row_kind) if "row_kind_override" not in options else int(options["row_kind_override"])
        procedure_code = int(row.procedure_code_felt) if "row_procedure_code_override" not in options else int(options["row_procedure_code_override"])
        policy_leaf_index = int(row.policy_leaf_index) if "row_policy_leaf_index_override" not in options else int(options["row_policy_leaf_index_override"])
        next_procedure_code = int(row.next_procedure_code_felt) if "row_next_procedure_code_override" not in options else int(options["row_next_procedure_code_override"])
        next_policy_leaf_index = int(row.next_policy_leaf_index) if "row_next_policy_leaf_index_override" not in options else int(options["row_next_policy_leaf_index_override"])
        statements.extend(
            [
                f"    let {var_name} = MultiLineFeeRowWitness {{",
                f"        row_kind: {row_kind}_u32,",
                f"        procedure_code: {procedure_code}_felt252,",
                f"        allowed_cents: {int(row.allowed_cents)}_u128,",
                f"        requires_tar: {requires_tar}_u32,",
                f"        policy_leaf_index: {policy_leaf_index}_u128,",
                f"        next_procedure_code: {next_procedure_code}_felt252,",
                f"        next_policy_leaf_index: {next_policy_leaf_index}_u128,",
                f"        policy_path_elements: {path}.span(),",
                "    };",
            ]
        )
    array_name = f"{prefix}_policy_rows"
    statements.append(f"    let mut {array_name} = ArrayTrait::new();")
    for row_var in row_vars:
        statements.append(f"    {array_name}.append({row_var});")
    return statements, array_name


def _authorization_literal(prefix: str, auth, *, options: dict[str, object] | None = None) -> tuple[list[str], str]:
    options = options or {}
    auth = options.get("auth_override") or auth
    auth_procedure_code = int(auth.procedure_code) if "auth_procedure_code_override" not in options else int(options["auth_procedure_code_override"])
    auth_line_index = int(auth.line_index) if "auth_line_index_override" not in options else int(options["auth_line_index_override"])
    auth_path = f"{prefix}_auth_path"
    statements = _array(auth_path, "felt252", _bump_path(auth.auth_path_elements, int(options.get("auth_path_delta", 0))))
    var_name = f"{prefix}_auth"
    statements.extend(
        [
            f"    let {var_name} = MultiLineAuthorizationWitness {{",
            f"        auth_proof_root: {int(auth.auth_proof.root, 16)}_felt252,",
            f"        auth_leaf_index: {int(auth.auth_leaf_index)}_u128,",
            f"        claim_id: {int(auth.claim_id)}_felt252,",
            f"        line_index: {auth_line_index}_u128,",
            f"        procedure_code: {auth_procedure_code}_felt252,",
            f"        service_date_day: {int(auth.service_date_day)}_u128,",
            f"        valid_from_day: {int(auth.valid_from_day)}_u128,",
            f"        valid_until_day: {int(auth.valid_until_day)}_u128,",
            f"        prior_authorization: {_pack_optional_felt_text(auth.prior_authorization)}_felt252,",
            f"        signed_tar_authorization_commitment: {int(auth.signed_tar_authorization_commitment) + int(options.get('auth_signed_delta', 0))}_felt252,",
            f"        authorization_present: {int(bool(auth.authorization_present))}_u32,",
            f"        signer_root: {int(auth.signer_root)}_felt252,",
            f"        fact_verification_commitment: {int(auth.fact_verification_commitment)}_felt252,",
            f"        evidence_root: {int(auth.evidence_root)}_felt252,",
            f"        auth_path_elements: {auth_path}.span(),",
            "    };",
        ]
    )
    return statements, var_name


def _claim_witness_literal(
    prefix: str,
    bundle,
    *,
    claim_id_override: int | None = None,
    service_date_day_override: int | None = None,
    total_charge_delta: int = 0,
    allowed_delta: int = 0,
    first_line_options: dict[str, object] | None = None,
    line_options_by_index: dict[int, dict[str, object]] | None = None,
) -> tuple[list[str], str]:
    line_array = f"{prefix}_lines"
    auth_array = f"{prefix}_auths"
    statements: list[str] = []
    line_vars: list[str] = []
    auth_options: dict[int, dict[str, object]] = {}
    for index, line in enumerate(bundle.service_lines):
        options = dict((line_options_by_index or {}).get(index, {}))
        if index == 0 and first_line_options:
            options.update(first_line_options)
        if bool(line.tar_required) and options:
            auth_options.setdefault(int(line.authorization_index), {}).update(options)
        line_statements, line_var = _line_literal(
            f"{prefix}_line_{index}",
            line,
            allowed_delta=allowed_delta if index == 0 else 0,
            **options,
        )
        statements.extend(line_statements)
        line_vars.append(line_var)
    auth_vars: list[str] = []
    for index, auth in enumerate(bundle.authorizations):
        auth_statements, auth_var = _authorization_literal(
            f"{prefix}_auth_{index}",
            auth,
            options=auth_options.get(index, {}),
        )
        statements.extend(auth_statements)
        auth_vars.append(auth_var)
    statements.append(f"    let mut {line_array} = ArrayTrait::new();")
    for line_var in line_vars:
        statements.append(f"    {line_array}.append({line_var});")
    statements.append(f"    let mut {auth_array} = ArrayTrait::new();")
    for auth_var in auth_vars:
        statements.append(f"    {auth_array}.append({auth_var});")
    var_name = f"{prefix}_claim"
    statements.extend(
        [
            f"    let {var_name} = MultiLineClaimWitness {{",
            f"        claim_id: {int(bundle.claim_id if claim_id_override is None else claim_id_override)}_felt252,",
            f"        service_date_day: {int(bundle.service_date_day if service_date_day_override is None else service_date_day_override)}_u128,",
            f"        total_charge_cents: {int(bundle.total_charge_cents) + total_charge_delta}_u128,",
            f"        service_lines: {line_array}.span(),",
            f"        authorizations: {auth_array}.span(),",
            "    };",
        ]
    )
    return statements, var_name


def _decision_input_literal(
    prefix: str,
    bundle,
    *,
    claim_bundle=None,
    lines_claim_id_override: int | None = None,
    lines_service_date_day_override: int | None = None,
    total_charge_delta: int = 0,
    allowed_delta: int = 0,
    first_line_options: dict[str, object] | None = None,
    line_options_by_index: dict[int, dict[str, object]] | None = None,
    member_id_override: int | None = None,
    provider_npi_override: int | None = None,
    diagnosis_count_override: int | None = None,
    fact_overrides: dict[str, int] | None = None,
) -> tuple[list[str], str]:
    claim_source_bundle = claim_bundle or bundle
    fact_overrides = fact_overrides or {}

    def fact_value(name: str, default: bool) -> int:
        return int(fact_overrides.get(name, int(bool(default))))

    claim_statements, claim_source_var = _claim_source_literal(prefix, claim_source_bundle.claim)
    nullifier_statements, nullifier_var = _nullifier_literal(prefix, claim_source_bundle.nullifier)
    fee_policy_statements, _fee_policy_var = _fee_policy_literal(prefix, bundle)
    policy_row_statements, _policy_rows_var = _policy_rows_literal(
        prefix,
        bundle,
        line_options_by_index=line_options_by_index,
        first_line_options=first_line_options,
    )
    facts_path = f"{prefix}_claim_facts_path"
    statements, claim_var = _claim_witness_literal(
        prefix,
        bundle,
        claim_id_override=lines_claim_id_override,
        service_date_day_override=lines_service_date_day_override,
        total_charge_delta=total_charge_delta,
        allowed_delta=allowed_delta,
        first_line_options=first_line_options,
        line_options_by_index=line_options_by_index,
    )
    statements = (
        claim_statements
        + nullifier_statements
        + fee_policy_statements
        + policy_row_statements
        + statements
    )
    statements.extend(_array(facts_path, "felt252", bundle.claim_facts_path_elements))
    var_name = f"{prefix}_input"
    statements.extend(
        [
            f"    let {var_name} = MultiLineDecisionInput {{",
            "        batch_id: 901_felt252,",
            f"        claim: {claim_source_var},",
            f"        claim_source_leaf: {int(claim_source_bundle.claim.claim_source_leaf)}_felt252,",
            f"        claim_facts_leaf: {int(bundle.claim_facts_leaf)}_felt252,",
            f"        claim_facts_leaf_index: {int(bundle.claim_facts_leaf_index)}_u128,",
            f"        claim_facts_path_elements: {facts_path}.span(),",
            f"        claim_facts_signer: {int(bundle.claim_facts_signer)}_felt252,",
            f"        claim_facts_verification_commitment: {int(bundle.claim_facts_verification_commitment)}_felt252,",
            f"        claim_facts_evidence_commitment: {int(bundle.claim_facts_evidence_commitment)}_felt252,",
            f"        member_id: {int(bundle.claim.member_id if member_id_override is None else member_id_override)}_felt252,",
            f"        provider_npi: {int(bundle.claim.provider_npi if provider_npi_override is None else provider_npi_override)}_felt252,",
            f"        diagnosis_count: {int(bundle.claim.diagnosis_count if diagnosis_count_override is None else diagnosis_count_override)}_u128,",
            f"        member_active: {fact_value('member_active', bundle.member_active)}_u32,",
            f"        provider_payable: {fact_value('provider_payable', bundle.provider_payable)}_u32,",
            f"        provider_not_suspended: {fact_value('provider_not_suspended', bundle.provider_not_suspended)}_u32,",
            f"        member_not_deceased: {fact_value('member_not_deceased', bundle.member_not_deceased)}_u32,",
            f"        duplicate_claim_attested: {fact_value('duplicate_claim_attested', bundle.duplicate_claim_attested)}_u32,",
            f"        integrity_hold_attested: {fact_value('integrity_hold_attested', bundle.integrity_hold_attested)}_u32,",
            f"        lines: {claim_var},",
            "    };",
        ]
    )
    return statements, var_name


def _phase3_case(
    name: str,
    bundle,
    *,
    expected_decision: int,
    expected_failure_code: int,
    expected_line_count: int,
    expected_sum: int,
    expected_allowed: int,
    expected_all_required_authorized: int | None = None,
    expected_all_charges_and_units_positive: int | None = None,
    expected_commitment: int | None = None,
    not_commitment: int | None = None,
) -> str:
    statements, input_var = _decision_input_literal(name, bundle)
    expected_auth = 1 if expected_all_required_authorized is None else expected_all_required_authorized
    expected_positive = (
        int(
            all(
                int(line.line_charge_cents) > 0 and int(line.units_cents) > 0
                for line in bundle.service_lines
            )
        )
        if expected_all_charges_and_units_positive is None
        else expected_all_charges_and_units_positive
    )
    expected_all_fee_rows_present = int(all(bool(line.policy_present) for line in bundle.service_lines))
    expected_nullifier_before = int(bundle.nullifier.live_root_before)
    expected_nullifier_after = int(bundle.nullifier.root_after)
    statements.extend(
        [
            f"    let math = {_math_call(input_var, bundle)};",
            f"    assert(math.line_count == {expected_line_count}_u128, 'kat line count');",
            f"    assert(math.sum_line_charge_cents == {expected_sum}_u128, 'kat sum');",
            f"    assert(math.allowed_total_cents == {expected_allowed}_u128, 'kat allowed');",
            f"    assert(math.all_required_authorized == {expected_auth}_u32, 'kat auth');",
            f"    assert(math.all_fee_rows_present == {expected_all_fee_rows_present}_u32, 'kat fee rows');",
            f"    assert(math.all_charges_and_units_positive == {expected_positive}_u32, 'kat positive money');",
            f"    let output = {_adjudicate_call(input_var, bundle)};",
            f"    assert(output.decision == {expected_decision}_u32, 'kat decision');",
            f"    assert(output.failure_code == {expected_failure_code}_u32, 'kat failure');",
            f"    assert(output.line_count == {expected_line_count}_u128, 'kat output count');",
            f"    assert(output.sum_line_charge_cents == {expected_sum}_u128, 'kat output sum');",
            f"    assert(output.allowed_cents == {expected_allowed}_u128, 'kat output allowed');",
            f"    assert(output.payment_cents == {expected_allowed if expected_decision == 1 else 0}_u128, 'kat payment');",
            f"    assert(output.nullifier_root_before == {expected_nullifier_before}_felt252, 'kat null before');",
            f"    assert(output.nullifier_root_after == {expected_nullifier_after}_felt252, 'kat null after');",
        ]
    )
    if expected_commitment is not None:
        statements.append(f"    assert(output.commitment == {int(expected_commitment)}_felt252, 'kat commitment');")
    if not_commitment is not None:
        statements.append(f"    assert(output.commitment != {int(not_commitment)}_felt252, 'kat old commitment');")
    return "\n".join(["#[test]", f"fn {name}() {{", *statements, "}"])


def _reject_case(
    name: str,
    bundle,
    *,
    claim_bundle=None,
    lines_claim_id_override: int | None = None,
    lines_service_date_day_override: int | None = None,
    total_charge_delta: int = 0,
    allowed_delta: int = 0,
    first_line_options: dict[str, object] | None = None,
    line_options_by_index: dict[int, dict[str, object]] | None = None,
    member_id_override: int | None = None,
    provider_npi_override: int | None = None,
    diagnosis_count_override: int | None = None,
    fact_overrides: dict[str, int] | None = None,
) -> str:
    statements, input_var = _decision_input_literal(
        name,
        bundle,
        claim_bundle=claim_bundle,
        lines_claim_id_override=lines_claim_id_override,
        lines_service_date_day_override=lines_service_date_day_override,
        total_charge_delta=total_charge_delta,
        allowed_delta=allowed_delta,
        first_line_options=first_line_options,
        line_options_by_index=line_options_by_index,
        member_id_override=member_id_override,
        provider_npi_override=provider_npi_override,
        diagnosis_count_override=diagnosis_count_override,
        fact_overrides=fact_overrides,
    )
    statements.extend(
        [
            f"    {_adjudicate_call(input_var, bundle, claim_bundle=claim_bundle)};",
        ]
    )
    return "\n".join(["#[test]", f"fn {name}() {{", *statements, "}"])


def _math_reject_case(
    name: str,
    bundle,
    *,
    total_charge_delta: int = 0,
    allowed_delta: int = 0,
    first_line_options: dict[str, object] | None = None,
) -> str:
    statements, input_var = _decision_input_literal(
        name,
        bundle,
        total_charge_delta=total_charge_delta,
        allowed_delta=allowed_delta,
        first_line_options=first_line_options,
    )
    statements.extend(
        [
            f"    {_math_call(input_var, bundle)};",
        ]
    )
    return "\n".join(["#[test]", f"fn {name}() {{", *statements, "}"])


def _required_code_as_adjacent_nonmember_options(procedure_code: str, config: BatchConfig) -> dict[str, object]:
    _ = procedure_code, config
    return {
        "tar_required_override": 0,
    }


def _remove_preserve_indices(tree: IndexedNullifierTree, victim: int) -> IndexedNullifierTree:
    removed = tree.clone()
    position = removed._sorted_values_list.index(victim)
    predecessor_value = removed._sorted_values_list[position - 1]
    successor_value = removed._sorted_values_list[position + 1]
    predecessor = removed._nodes[removed._value_to_index[predecessor_value]]
    successor = removed._nodes[removed._value_to_index[successor_value]]
    victim_index = removed._value_to_index[victim]
    removed._nodes[predecessor.index] = IndexedLeaf(
        predecessor.index,
        predecessor.value,
        successor.value,
        successor.index,
    )
    del removed._nodes[victim_index]
    del removed._value_to_index[victim]
    removed._sorted_values_list.remove(victim)
    removed._root_cache = None
    return removed


def _neighbor_values_for(value: int) -> list[int]:
    if not (1_000 < value < MAX_NULLIFIER - 1_000):
        raise AssertionError("test nullifier unexpectedly near sentinel boundary")
    return [value - 300, value - 200, value - 100, value + 100, value + 200, value + 300]


def _eviction_nullifier_for(value: int):
    real = IndexedNullifierTree(_neighbor_values_for(value))
    base = real.prove_nonmembership(value)
    second = _remove_preserve_indices(real, value + 200)
    second.insert(value)
    root_after, inserted_path, inserted_indices = second._root_and_path(base.insertedIndex)
    return _nullifier_transition_witness_from_nonmembership(
        replace(
            base,
            rootAfter=root_after,
            insertedPathElements=inserted_path,
            insertedPathIndices=inserted_indices,
        )
    )


def _occupied_slot_nullifier_for(value: int):
    real = IndexedNullifierTree(_neighbor_values_for(value))
    base = real.prove_nonmembership(value)
    victim_index = real._value_to_index[value + 200]
    second = real.clone()
    predecessor = second._nodes[base.leafIndex]
    second._nodes[predecessor.index] = IndexedLeaf(
        predecessor.index,
        predecessor.value,
        base.nullifier,
        victim_index,
    )
    second._nodes[victim_index] = IndexedLeaf(
        victim_index,
        base.nullifier,
        base.nextValue,
        base.nextIndex,
    )
    second._root_cache = None
    root_after, inserted_path, inserted_indices = second._root_and_path(victim_index)
    return _nullifier_transition_witness_from_nonmembership(
        replace(
            base,
            insertedIndex=victim_index,
            rootAfter=root_after,
            insertedPathElements=inserted_path,
            insertedPathIndices=inserted_indices,
        )
    )


def _approved_claim_context():
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
    resolved = resolve_claim_facts(ctx, flags=payload["flags"], fee_schedule_cents=config.fee_schedule_cents)
    ctx = replace(
        ctx,
        flags=resolved.flags,
        fact_verification={**ctx.fact_verification, **resolved.fact_verification},
    )
    result, engine_mode = adjudicate_for_batch(ctx)
    if not result.approved:
        raise AssertionError(result.denial_reason)
    return ctx, result, resolved.evidence_packet.evidence_root, config, engine_mode


def _manual_context(
    service_lines: list[ServiceLine],
    service_date: str = "20260601",
    claim_id: str = "BL-MULTI-LINE-PHASE3",
) -> SharedContext:
    os.environ.setdefault("BL_DEV", "1")
    required_tar_lines = [line for line in service_lines if is_tar_required(line.procedure_code)]
    tar_verified = bool(required_tar_lines) and all(line.prior_authorization for line in required_tar_lines)
    return SharedContext(
        claim_id=claim_id,
        transaction_set="837",
        payer_id="CA-MMIS",
        member_id="M123456789",
        patient=Patient(name="DOE JANE", id="M123456789"),
        provider=Provider(npi="1999999984", name="ADAMS ALICE"),
        service_date=service_date,
        diagnoses=["F840"],
        service_lines=service_lines,
        total_charge=round(sum(float(line.charge_amount) for line in service_lines), 2),
        flags={
            "eligibility_active": True,
            "provider_enrolled": True,
            "provider_not_suspended": True,
            "not_deceased": True,
            "duplicate_claim": False,
            "program_integrity_hold": False,
        },
        fact_verification={"tar_authorization": "VERIFIED" if tar_verified else "UNVERIFIED"},
    )


@unittest.skipUnless(shutil.which("scarb"), "scarb unavailable")
class MultiLineCairoPhase3KatTests(unittest.TestCase):
    def test_phase3_cairo_multiline_money_math_n1_and_n2(self) -> None:
        one_line = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        two_line = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        body = "\n\n".join(
            [
                _phase3_case(
                    "phase3_n1_approved_math",
                    one_line,
                    expected_decision=1,
                    expected_failure_code=0,
                    expected_line_count=1,
                    expected_sum=one_line.sum_line_charge_cents,
                    expected_allowed=one_line.allowed_total_cents,
                ),
                _phase3_case(
                    "phase3_n2_approved_math",
                    two_line,
                    expected_decision=1,
                    expected_failure_code=0,
                    expected_line_count=2,
                    expected_sum=two_line.sum_line_charge_cents,
                    expected_allowed=two_line.allowed_total_cents,
                ),
            ]
        )
        output = _run_cairo("multi_line_phase3_math_kat", body)
        self.assertIn("2 passed", output)

    def test_phase3_zero_charge_and_units_are_private_g8a_denials(self) -> None:
        zero_charge = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 0.00, 1.0, None)]),
            config=BatchConfig(),
        )
        zero_units = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 0.0, None)]),
            config=BatchConfig(),
        )
        one_zero_line = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 0.00, 1.0, None),
                    ServiceLine("2", "99213", 125.00, 1.0, None),
                ]
            ),
            config=BatchConfig(),
        )
        body = "\n\n".join(
            [
                _phase3_case(
                    "phase3_zero_charge_is_g8a_denial",
                    zero_charge,
                    expected_decision=0,
                    expected_failure_code=10,
                    expected_line_count=1,
                    expected_sum=0,
                    expected_allowed=0,
                    expected_all_charges_and_units_positive=0,
                ),
                _phase3_case(
                    "phase3_zero_units_is_g8a_denial",
                    zero_units,
                    expected_decision=0,
                    expected_failure_code=10,
                    expected_line_count=1,
                    expected_sum=12500,
                    expected_allowed=12500,
                    expected_all_charges_and_units_positive=0,
                ),
                _phase3_case(
                    "phase3_one_zero_line_is_g8a_denial",
                    one_zero_line,
                    expected_decision=0,
                    expected_failure_code=10,
                    expected_line_count=2,
                    expected_sum=12500,
                    expected_allowed=12500,
                    expected_all_charges_and_units_positive=0,
                ),
            ]
        )
        output = _run_cairo("multi_line_phase3_zero_money_kat", body)
        self.assertIn("3 passed", output)

    def test_phase3_u32_max_plus_one_rejects_each_money_field(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        u32_max_plus_one = 1 << 32
        body = "\n\n".join(
            [
                _math_reject_case(
                    "phase3_u32_max_plus_one_total_rejects",
                    bundle,
                    total_charge_delta=u32_max_plus_one - bundle.total_charge_cents,
                ),
                _math_reject_case(
                    "phase3_u32_max_plus_one_line_rejects",
                    bundle,
                    first_line_options={"line_charge_cents_override": u32_max_plus_one},
                ),
                _math_reject_case(
                    "phase3_u32_max_plus_one_units_rejects",
                    bundle,
                    first_line_options={"units_cents_override": u32_max_plus_one},
                ),
            ]
        )
        output = _run_cairo("multi_line_phase3_u32_boundary_kat", body, check=False)
        self.assertIn("multi total range", output)
        self.assertIn("multi line range", output)
        self.assertIn("multi units range", output)
        self.assertNotIn("3 passed", output)

    def test_foundation_variable_length_text_order_matches_cairo(self) -> None:
        config = BatchConfig(
            fee_schedule_cents={"Z9": 12_500, "A10": 12_500},
            tar_required_procedure_codes=("T1019",),
        )
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("2", "A10", 125.00, 1.0, None),
                    ServiceLine("1", "Z9", 125.00, 1.0, None),
                ]
            ),
            config=config,
        )
        self.assertEqual(
            [line.procedure_code for line in bundle.service_lines],
            ["Z9", "A10"],
        )
        body = _phase3_case(
            "foundation_variable_length_text_order_matches_cairo",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=25_000,
            expected_allowed=25_000,
        )
        output = _run_cairo("foundation_variable_length_text_order_kat", body)
        self.assertIn("1 passed", output)

    def test_phase3_allowed_total_uses_per_line_min_when_charge_exceeds_fee(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 200.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        over_fee_line = next(line for line in bundle.service_lines if line.procedure_code == "99213")

        self.assertEqual(over_fee_line.line_charge_cents, 20000)
        self.assertEqual(over_fee_line.allowed_cents, 12500)
        self.assertEqual(bundle.sum_line_charge_cents, 32500)
        self.assertEqual(bundle.allowed_total_cents, 25000)
        self.assertLess(bundle.allowed_total_cents, bundle.sum_line_charge_cents)

        body = _phase3_case(
            "phase3_allowed_total_uses_per_line_min",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=32500,
            expected_allowed=25000,
        )
        output = _run_cairo("multi_line_phase3_per_line_min_kat", body)
        self.assertIn("1 passed", output)

    def test_phase8_max_50_line_claim_accepts_in_multiline_path(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [ServiceLine(str(index + 1), "99213", 125.00, 1.0, None) for index in range(50)]
            ),
            config=BatchConfig(),
        )

        self.assertEqual(len(bundle.service_lines), 50)
        self.assertEqual(bundle.sum_line_charge_cents, 625000)
        self.assertEqual(bundle.allowed_total_cents, 625000)

        body = _phase3_case(
            "phase8_max_50_line_claim_accepts",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=50,
            expected_sum=625000,
            expected_allowed=625000,
            expected_commitment=multi_line_claim_payment_commitment(bundle),
        )
        output = _run_cairo("multi_line_phase8_max_50_line_kat", body)
        self.assertIn("1 passed", output)

    def test_phase8_non_boolean_fact_values_reject(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = "\n\n".join(
            [
                _reject_case(
                    "phase8_member_active_value_two_rejects",
                    bundle,
                    fact_overrides={"member_active": 2},
                ),
                _reject_case(
                    "phase8_provider_payable_large_u32_rejects",
                    bundle,
                    fact_overrides={"provider_payable": 4294967295},
                ),
            ]
        )
        output = _run_cairo("multi_line_phase8_boolean_fact_reject_kat", body, check=False)
        self.assertIn("fact member", output)
        self.assertIn("fact provider", output)
        self.assertNotIn("2 passed", output)

        large_felt_body = _reject_case("phase8_provider_payable_large_felt_rejects", bundle)
        large_felt_body = large_felt_body.replace(
            "provider_payable: 1_u32,",
            f"provider_payable: {FIELD_MODULUS - 1}_felt252,",
        )
        large_felt_output = _run_cairo("multi_line_phase8_large_felt_fact_reject_kat", large_felt_body, check=False)
        self.assertIn('Expected: "core::integer::u32", found: "core::felt252"', large_felt_output)

    def test_phase4_authenticated_policy_membership_accepts(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        self.assertTrue(bundle.service_lines[0].policy_present)
        body = _phase3_case(
            "phase4_authenticated_policy_membership_accepts",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=1,
            expected_sum=12500,
            expected_allowed=12500,
            expected_all_required_authorized=1,
        )
        output = _run_cairo("multi_line_phase4_policy_membership_kat", body)
        self.assertIn("1 passed", output)

    def test_phase4_authenticated_policy_absence_denies_fee_gate(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "ZZ999", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        self.assertFalse(bundle.service_lines[0].policy_present)
        body = _phase3_case(
            "phase4_authenticated_policy_absence_denies_fee_gate",
            bundle,
            expected_decision=0,
            expected_failure_code=11,
            expected_line_count=1,
            expected_sum=12500,
            expected_allowed=0,
        )
        output = _run_cairo("multi_line_phase4_policy_absence_kat", body)
        self.assertIn("1 passed", output)

    def test_phase4_existing_policy_member_cannot_be_forged_as_absent(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase4_existing_policy_member_forged_as_absent_rejects",
            bundle,
            first_line_options={"policy_present_override": 0},
        )
        output = _run_cairo("multi_line_phase4_false_absence_reject_kat", body, check=False)
        self.assertIn("multi policy absent lower", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_forged_policy_successor_rejects_against_governed_root(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "ZZ999", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase4_forged_policy_successor_rejects",
            bundle,
            first_line_options={
                "row_next_procedure_code_override": pack_felt_text("ZZ999") + 1,
            },
        )
        output = _run_cairo("multi_line_phase4_forged_successor_reject_kat", body, check=False)
        self.assertIn("multi policy row path", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_omitted_policy_evidence_rejects(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "ZZ999", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase4_omitted_policy_evidence_rejects",
            bundle,
            first_line_options={"policy_row_index_override": len(bundle.policy_rows)},
        )
        output = _run_cairo("multi_line_phase4_omitted_policy_reject_kat", body, check=False)
        self.assertIn("multi policy dict index", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_fee_leaf_override_is_not_representable(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        statements, input_var = _decision_input_literal(
            "phase4_fee_leaf_override_not_representable",
            bundle,
            first_line_options={"fee_leaf_override": fee_row_leaf("T1019", bundle.service_lines[0].allowed_cents)},
        )
        statements.extend(
            [
                f"    let output = {_adjudicate_call(input_var, bundle)};",
                "    assert(output.decision == 1_u32, 'kat decision');",
                "    assert(output.payment_cents == 12500_u128, 'kat payment');",
            ]
        )
        body = "\n".join(["#[test]", "fn phase4_fee_leaf_override_not_representable() {", *statements, "}"])
        output = _run_cairo("multi_line_phase4_fee_leaf_not_representable_kat", body)
        self.assertIn("1 passed", output)

    def test_phase4_rejects_allowed_amount_inflated_above_fee_schedule(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 200.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase4_inflated_allowed_rejects", bundle, allowed_delta=100)
        output = _run_cairo("multi_line_phase4_inflated_allowed_reject_kat", body, check=False)
        self.assertIn("multi policy dict allowed", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_below_cap_charge_uses_authenticated_fee_then_per_line_min(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 100.00, 1.0, None)]),
            config=BatchConfig(),
        )
        line = bundle.service_lines[0]

        self.assertEqual(line.line_charge_cents, 10000)
        self.assertEqual(line.allowed_cents, 12500)

        body = _phase3_case(
            "phase4_below_cap_charge_uses_per_line_min",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=1,
            expected_sum=10000,
            expected_allowed=10000,
        )
        output = _run_cairo("multi_line_phase4_below_cap_charge_kat", body)
        self.assertIn("1 passed", output)

    def test_phase4_rejects_tar_required_line_presented_as_nonmember(self) -> None:
        config = BatchConfig()
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=config,
        )
        body = _reject_case(
            "phase4_tar_required_as_nonmember_rejects",
            bundle,
            first_line_options=_required_code_as_adjacent_nonmember_options("T1019", config),
        )
        output = _run_cairo("multi_line_phase4_tar_nonmember_reject_kat", body, check=False)
        self.assertIn("multi policy row path", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_rejects_tampered_policy_path(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase4_tampered_policy_path_rejects",
            bundle,
            first_line_options={"fee_path_delta": 1},
        )
        output = _run_cairo("multi_line_phase4_policy_path_reject_kat", body, check=False)
        self.assertIn("multi policy row path", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_rejects_tampered_policy_requires_tar(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase4_tampered_policy_requires_tar_rejects",
            bundle,
            first_line_options={"tar_required_override": 0},
        )
        output = _run_cairo("multi_line_phase4_policy_tar_flag_reject_kat", body, check=False)
        self.assertIn("multi policy row path", output)
        self.assertNotIn("1 passed", output)

    def test_phase4_duplicate_identical_lines_verify_as_two_billable_lines(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "99213", 125.00, 1.0, None),
                ]
            ),
            config=BatchConfig(),
        )
        self.assertEqual(len(bundle.service_lines), 2)
        self.assertEqual(bundle.service_lines[0].fee_leaf, bundle.service_lines[1].fee_leaf)
        body = _phase3_case(
            "phase4_duplicate_identical_lines_billable",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=25000,
            expected_allowed=25000,
        )
        output = _run_cairo("multi_line_phase4_duplicate_lines_kat", body)
        self.assertIn("1 passed", output)

    def test_phase5_two_tar_required_lines_one_missing_auth_denies_g7(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK"),
                    ServiceLine("2", "S5102", 125.00, 1.0, None),
                ]
            ),
            config=BatchConfig(),
        )
        self.assertTrue(any(line.prior_authorization for line in bundle.service_lines))
        self.assertTrue(all(line.tar_required for line in bundle.service_lines))

        body = _phase3_case(
            "phase5_one_required_line_missing_auth_denies",
            bundle,
            expected_decision=0,
            expected_failure_code=9,
            expected_line_count=2,
            expected_sum=25000,
            expected_allowed=25000,
            expected_all_required_authorized=0,
        )
        output = _run_cairo("multi_line_phase5_missing_auth_denial_kat", body)
        self.assertIn("1 passed", output)

    def test_phase5_unverified_prior_auth_token_denies_g7_instead_of_authenticating(self) -> None:
        ctx = _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-UNVERIFIED")])
        ctx = replace(ctx, fact_verification={"tar_authorization": "UNVERIFIED"})
        bundle = build_multi_line_service_line_witness(ctx, config=BatchConfig())

        self.assertFalse(bundle.authorizations[0].authorization_present)
        self.assertEqual(bundle.authorizations[0].signed_tar_authorization_commitment, 0)
        body = _phase3_case(
            "phase5_unverified_prior_auth_denies_g7",
            bundle,
            expected_decision=0,
            expected_failure_code=9,
            expected_line_count=1,
            expected_sum=12500,
            expected_allowed=12500,
            expected_all_required_authorized=0,
        )
        output = _run_cairo("multi_line_phase5_unverified_prior_auth_kat", body)
        self.assertIn("1 passed", output)

    def test_phase5_aggregate_style_authorized_claim_still_denies_without_per_line_auth(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK"),
                    ServiceLine("2", "H2015", 125.00, 1.0, None),
                ]
            ),
            config=BatchConfig(),
        )
        aggregate_authorization_would_be_true = any(line.prior_authorization for line in bundle.service_lines)
        self.assertTrue(aggregate_authorization_would_be_true)

        body = _phase3_case(
            "phase5_aggregate_shortcut_removed",
            bundle,
            expected_decision=0,
            expected_failure_code=9,
            expected_line_count=2,
            expected_sum=25000,
            expected_allowed=25000,
            expected_all_required_authorized=0,
        )
        output = _run_cairo("multi_line_phase5_aggregate_shortcut_removed_kat", body)
        self.assertIn("1 passed", output)

    def test_phase5_auth_proof_for_wrong_procedure_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase5_auth_wrong_procedure_rejects",
            bundle,
            first_line_options={"auth_procedure_code_override": pack_felt_text("99213")},
        )
        output = _run_cairo("multi_line_phase5_auth_wrong_procedure_kat", body, check=False)
        self.assertIn("multi auth procedure", output)
        self.assertNotIn("1 passed", output)

    def test_phase5_auth_proof_for_wrong_canonical_line_index_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase5_auth_wrong_line_index_rejects",
            bundle,
            first_line_options={"auth_line_index_override": 1},
        )
        output = _run_cairo("multi_line_phase5_auth_wrong_line_index_kat", body, check=False)
        self.assertIn("multi auth line index", output)
        self.assertNotIn("1 passed", output)

    def test_phase5_tampered_oracle_auth_path_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase5_auth_path_tamper_rejects",
            bundle,
            first_line_options={"auth_path_delta": 1},
        )
        output = _run_cairo("multi_line_phase5_auth_path_tamper_kat", body, check=False)
        self.assertIn("multi auth path", output)
        self.assertNotIn("1 passed", output)

    def test_phase5_signed_prior_auth_commitment_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase5_signed_prior_auth_mismatch_rejects",
            bundle,
            first_line_options={"auth_signed_delta": 1},
        )
        output = _run_cairo("multi_line_phase5_signed_auth_mismatch_kat", body, check=False)
        self.assertIn("multi auth signed token", output)
        self.assertNotIn("1 passed", output)

    def test_phase5_non_tar_line_without_auth_is_not_denied_for_g7(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        self.assertFalse(bundle.requires_any_tar)
        body = _phase3_case(
            "phase5_non_tar_without_auth_approved",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=1,
            expected_sum=12500,
            expected_allowed=12500,
            expected_all_required_authorized=1,
        )
        output = _run_cairo("multi_line_phase5_non_tar_without_auth_kat", body)
        self.assertIn("1 passed", output)

    def test_phase5_duplicate_identical_tar_lines_cannot_share_one_auth_proof(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK"),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        self.assertEqual(len(bundle.service_lines), 2)
        self.assertEqual(bundle.service_lines[0].procedure_code, bundle.service_lines[1].procedure_code)
        self.assertNotEqual(bundle.service_lines[0].authorization.auth_leaf, bundle.service_lines[1].authorization.auth_leaf)

        valid_body = _phase3_case(
            "phase5_duplicate_tar_lines_distinct_auth_proofs_approve",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=25000,
            expected_allowed=25000,
            expected_all_required_authorized=1,
        )
        valid_output = _run_cairo("multi_line_phase5_duplicate_tar_distinct_auth_kat", valid_body)
        self.assertIn("1 passed", valid_output)

        forged_body = _reject_case(
            "phase5_duplicate_tar_lines_shared_auth_rejects",
            bundle,
            line_options_by_index={1: {"auth_override": bundle.service_lines[0].authorization}},
        )
        forged_output = _run_cairo("multi_line_phase5_duplicate_tar_shared_auth_kat", forged_body, check=False)
        self.assertIn("multi auth line index", forged_output)
        self.assertNotIn("1 passed", forged_output)

    def test_phase6_substituted_line_rejects_at_claim_source_binding(self) -> None:
        committed = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        forged_lines = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "S5102", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase6_substituted_line_binding_rejects",
            forged_lines,
            claim_bundle=committed,
        )
        output = _run_cairo("multi_line_phase6_substituted_line_kat", body, check=False)
        self.assertIn("multi claim service lines", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_omitted_line_rejects_at_claim_source_binding(self) -> None:
        committed = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        omitted = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase6_omitted_line_binding_rejects", omitted, claim_bundle=committed)
        output = _run_cairo("multi_line_phase6_omitted_line_kat", body, check=False)
        self.assertIn("multi claim service lines", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_added_line_rejects_at_claim_source_binding(self) -> None:
        committed = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        added = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        body = _reject_case("phase6_added_line_binding_rejects", added, claim_bundle=committed)
        output = _run_cairo("multi_line_phase6_added_line_kat", body, check=False)
        self.assertIn("multi claim service lines", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_reordered_distinct_lines_rejects_at_canonical_order_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        reordered = replace(bundle, service_lines=tuple(reversed(bundle.service_lines)))
        body = _reject_case("phase6_reordered_lines_binding_rejects", reordered)
        output = _run_cairo("multi_line_phase6_reordered_lines_kat", body, check=False)
        self.assertIn("multi line canonical order", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_duplicate_tar_lines_require_two_claim_source_occurrences(self) -> None:
        committed = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK"),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        one_occurrence = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")]),
            config=BatchConfig(),
        )
        valid_body = _phase3_case(
            "phase6_duplicate_tar_two_occurrences_pass",
            committed,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=25000,
            expected_allowed=25000,
            expected_all_required_authorized=1,
        )
        valid_output = _run_cairo("multi_line_phase6_duplicate_tar_two_occurrences_kat", valid_body)
        self.assertIn("1 passed", valid_output)

        forged_body = _reject_case(
            "phase6_duplicate_tar_one_occurrence_rejects",
            one_occurrence,
            claim_bundle=committed,
        )
        forged_output = _run_cairo("multi_line_phase6_duplicate_tar_one_occurrence_kat", forged_body, check=False)
        self.assertIn("multi claim service lines", forged_output)
        self.assertNotIn("1 passed", forged_output)

    def test_phase6_duplicate_tar_lines_still_reject_shared_auth_proof(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK"),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        forged_body = _reject_case(
            "phase6_duplicate_tar_shared_auth_still_rejects",
            bundle,
            line_options_by_index={1: {"auth_override": bundle.service_lines[0].authorization}},
        )
        forged_output = _run_cairo("multi_line_phase6_duplicate_tar_shared_auth_kat", forged_body, check=False)
        self.assertIn("multi auth line index", forged_output)
        self.assertNotIn("1 passed", forged_output)

    def test_phase6_claim_id_link_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase6_claim_id_link_rejects",
            bundle,
            lines_claim_id_override=bundle.claim_id + 1,
        )
        output = _run_cairo("multi_line_phase6_claim_id_link_kat", body, check=False)
        self.assertIn("multi claim id link", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_service_date_link_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case(
            "phase6_service_date_link_rejects",
            bundle,
            lines_service_date_day_override=bundle.service_date_day + 1,
        )
        output = _run_cairo("multi_line_phase6_service_date_link_kat", body, check=False)
        self.assertIn("multi claim service date link", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_total_charge_link_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase6_total_charge_link_rejects", bundle, total_charge_delta=1)
        output = _run_cairo("multi_line_phase6_total_charge_link_kat", body, check=False)
        self.assertIn("multi claim total link", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_member_link_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase6_member_link_rejects", bundle, member_id_override=bundle.claim.member_id + 1)
        output = _run_cairo("multi_line_phase6_member_link_kat", body, check=False)
        self.assertIn("multi claim member link", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_provider_link_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase6_provider_link_rejects", bundle, provider_npi_override=bundle.claim.provider_npi + 1)
        output = _run_cairo("multi_line_phase6_provider_link_kat", body, check=False)
        self.assertIn("multi claim provider link", output)
        self.assertNotIn("1 passed", output)

    def test_phase6_diagnosis_count_link_mismatch_rejects_specific_assert(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase6_diagnosis_link_rejects", bundle, diagnosis_count_override=bundle.claim.diagnosis_count + 1)
        output = _run_cairo("multi_line_phase6_diagnosis_link_kat", body, check=False)
        self.assertIn("multi claim diagnosis link", output)
        self.assertNotIn("1 passed", output)

    def test_phase7_payment_commitment_uses_aggregate_line_fingerprint(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 200.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        expected_commitment = multi_line_claim_payment_commitment(bundle)
        old_single_fee_commitment = _old_single_fee_payment_commitment(bundle)

        self.assertEqual(bundle.allowed_total_cents, 25000)
        self.assertEqual(bundle.sum_line_charge_cents, 32500)
        self.assertNotEqual(expected_commitment, old_single_fee_commitment)

        body = _phase3_case(
            "phase7_payment_commitment_uses_aggregate_line_fingerprint",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=32500,
            expected_allowed=25000,
            expected_all_required_authorized=1,
            expected_commitment=expected_commitment,
            not_commitment=old_single_fee_commitment,
        )
        output = _run_cairo("multi_line_phase7_payment_commitment_kat", body)
        self.assertIn("1 passed", output)

    def test_phase7_rejects_old_single_fee_payment_commitment(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 200.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        old_single_fee_commitment = _old_single_fee_payment_commitment(bundle)
        statements, input_var = _decision_input_literal("phase7_old_single_fee_commitment_rejects", bundle)
        statements.extend(
            [
                f"    let output = {_adjudicate_call(input_var, bundle)};",
                f"    assert(output.commitment == {old_single_fee_commitment}_felt252, 'phase7 old commitment');",
            ]
        )
        body = "\n".join(["#[test]", "fn phase7_old_single_fee_commitment_rejects() {", *statements, "}"])
        output = _run_cairo("multi_line_phase7_old_commitment_reject_kat", body, check=False)
        self.assertIn("phase7 old commitment", output)
        self.assertNotIn("1 passed", output)

    def test_phase7_multiline_claim_output_feeds_existing_batch_leaf(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 200.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        output = {
            "commitment": multi_line_claim_payment_commitment(bundle),
            "decision": 1,
            "failure_code": 0,
            "allowed_cents": bundle.allowed_total_cents,
            "payment_cents": bundle.allowed_total_cents,
        }
        changed_payment = dict(output)
        changed_payment["payment_cents"] += 1

        leaf = batch_output_leaf_for_claim_output(output, bundle.claim.claim_id)
        changed_leaf = batch_output_leaf_for_claim_output(changed_payment, bundle.claim.claim_id)

        self.assertEqual(output["allowed_cents"], 25000)
        self.assertEqual(output["payment_cents"], 25000)
        self.assertNotEqual(leaf, changed_leaf)

    def test_phase75_valid_multiline_nullifier_transition_outputs_verified_root(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 200.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        self.assertNotEqual(bundle.nullifier.live_root_before, bundle.nullifier.root_after)
        body = _phase3_case(
            "phase75_valid_nullifier_transition_outputs_verified_root",
            bundle,
            expected_decision=1,
            expected_failure_code=0,
            expected_line_count=2,
            expected_sum=32500,
            expected_allowed=25000,
            expected_all_required_authorized=1,
            expected_commitment=multi_line_claim_payment_commitment(bundle),
        )
        output = _run_cairo("multi_line_phase75_valid_nullifier_kat", body)
        self.assertIn("1 passed", output)

    def test_phase75_replayed_duplicate_multiline_nullifier_rejects_nonmembership_range(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        tree = IndexedNullifierTree()
        tree.insert(_inserted_nullifier(bundle))
        duplicate = tree.duplicate_rejection_witness(_inserted_nullifier(bundle))
        forged = replace(bundle, nullifier=_nullifier_transition_witness_from_nonmembership(duplicate))
        body = _reject_case("phase75_replayed_duplicate_nullifier_rejects", forged)
        output = _run_cairo("multi_line_phase75_duplicate_nullifier_reject_kat", body, check=False)
        self.assertIn("null high range", output)
        self.assertNotIn("1 passed", output)

    def test_phase75_tampered_nullifier_root_after_rejects(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        forged_nullifier = replace(
            bundle.nullifier,
            root_after=(int(bundle.nullifier.root_after) + 1) % FIELD_MODULUS,
            onchain_root_after=(int(bundle.nullifier.root_after) + 1) % FIELD_MODULUS,
        )
        forged = replace(bundle, nullifier=forged_nullifier)
        body = _reject_case("phase75_tampered_nullifier_root_after_rejects", forged)
        output = _run_cairo("multi_line_phase75_root_after_reject_kat", body, check=False)
        self.assertIn("null after root", output)
        self.assertNotIn("1 passed", output)

    def test_phase75_eviction_and_occupied_slot_exploits_reject_in_multiline_path(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        eviction = replace(bundle, nullifier=_eviction_nullifier_for(_inserted_nullifier(bundle)))
        occupied = replace(bundle, nullifier=_occupied_slot_nullifier_for(_inserted_nullifier(bundle)))
        body = "\n\n".join(
            [
                _reject_case("phase75_eviction_exploit_rejects", eviction),
                _reject_case("phase75_occupied_slot_exploit_rejects", occupied),
            ]
        )
        output = _run_cairo("multi_line_phase75_eviction_occupied_reject_kat", body, check=False)
        self.assertIn("null ins sibling", output)
        self.assertIn("null pred sibling", output)
        self.assertNotIn("2 passed", output)

    def test_phase75_two_distinct_multiline_claims_thread_nullifier_root(self) -> None:
        tree = IndexedNullifierTree()
        first = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
            nullifier_tree=tree,
        )
        tree.insert(_inserted_nullifier(first))
        second = build_multi_line_service_line_witness(
            _manual_context(
                [ServiceLine("1", "99213", 125.00, 1.0, None)],
                service_date="20260602",
                claim_id="BL-MULTI-LINE-PHASE3-SECOND",
            ),
            config=BatchConfig(),
            nullifier_tree=tree,
        )
        self.assertEqual(second.nullifier.live_root_before, first.nullifier.root_after)
        first_statements, first_input = _decision_input_literal("phase75_thread_first", first)
        second_statements, second_input = _decision_input_literal("phase75_thread_second", second)
        body = "\n".join(
            [
                "#[test]",
                "fn phase75_two_claims_thread_nullifier_roots() {",
                *first_statements,
                f"    let first_output = {_adjudicate_call(first_input, first)};",
                "    assert(first_output.decision == 1_u32, 'thread first decision');",
                *second_statements,
                f"    let second_output = {_adjudicate_call(second_input, second)};",
                "    assert(second_output.decision == 1_u32, 'thread second decision');",
                "    assert(first_output.nullifier_root_after == second_output.nullifier_root_before, 'thread root');",
                f"    assert(second_output.nullifier_root_after == {int(second.nullifier.root_after)}_felt252, 'thread after');",
                "}",
            ]
        )
        output = _run_cairo("multi_line_phase75_threaded_nullifier_kat", body)
        self.assertIn("1 passed", output)

    def test_phase8_n1_equivalence_with_python_engine_result(self) -> None:
        ctx, result, evidence_root, config, engine_mode = _approved_claim_context()
        _ = evidence_root, engine_mode
        multi = build_multi_line_service_line_witness(ctx, config=config)
        expected = claim_output_for_multi_line_witness(multi)
        self.assertEqual(expected["decision"], int(bool(result.approved)))
        body = _phase3_case(
            "phase8_n1_equivalence_with_python_engine",
            multi,
            expected_decision=expected["decision"],
            expected_failure_code=expected["failure_code"],
            expected_line_count=1,
            expected_sum=multi.sum_line_charge_cents,
            expected_allowed=expected["allowed_cents"],
        )
        output = _run_cairo("multi_line_phase3_equivalence_kat", body)
        self.assertIn("1 passed", output)

    def test_phase3_rejects_line_allowed_not_equal_to_authenticated_policy_row(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context([ServiceLine("1", "99213", 125.00, 1.0, None)]),
            config=BatchConfig(),
        )
        body = _reject_case("phase3_allowed_policy_mismatch_rejects", bundle, allowed_delta=1)
        output = _run_cairo("multi_line_phase3_allowed_reject_kat", body, check=False)
        self.assertIn("multi policy dict allowed", output)
        self.assertNotIn("1 passed", output)

    def test_phase3_rejects_one_cent_total_charge_mismatch(self) -> None:
        bundle = build_multi_line_service_line_witness(
            _manual_context(
                [
                    ServiceLine("1", "99213", 125.00, 1.0, None),
                    ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
                ]
            ),
            config=BatchConfig(),
        )
        body = _math_reject_case("phase3_total_sum_mismatch_rejects", bundle, total_charge_delta=1)
        output = _run_cairo("multi_line_phase3_total_reject_kat", body, check=False)
        self.assertIn("multi total mismatch", output)
        self.assertNotIn("1 passed", output)


if __name__ == "__main__":
    unittest.main()
