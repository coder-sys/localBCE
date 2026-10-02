"""Synthetic Trust Graph input vectors for tests (moved out of the product module)."""

from app.mirror.provider_trust_graph import *  # noqa: F403


def _source_for_demo(source_id: str, source_kind: str, *, observation_time: int, records: list[dict[str, object]], complete: bool = True, nonmembership: list[str] | None = None, end: int = 9_000) -> dict[str, object]:
    is_credential = source_kind == SOURCE_CREDENTIAL_KIND
    source: dict[str, object] = {
        "source_id": source_id,
        "source_kind": source_kind,
        "coverage_scope": SCOPE,
        "coverage_observation_time": observation_time,
        "coverage_effective_start": 6_000,
        "coverage_effective_end": end,
        "coverage_complete": complete,
        "coverage_authority_id": AUTH_CREDENTIAL_ID if is_credential else AUTH_ENROLLMENT_ID,
        "nonmembership_keys": [] if nonmembership is None else nonmembership,
        "records": records,
        "provenance": {
            "provenance_id": PROVENANCE_CREDENTIAL_ID if is_credential else PROVENANCE_ENROLLMENT_ID,
            "integrity_digest": "0" * 128,
        },
    }
    source["provenance"]["integrity_digest"] = source_integrity_digest(source)  # type: ignore[index]
    return source


def _demo_record(kind: str, *, record_number: int = 1, observation_time: int = 7_000, valid_until: int = 9_000, status: str = STATUS_ACTIVE, terminated_at: int = 0) -> dict[str, object]:
    prefix = "CREDENTIAL" if kind == "CREDENTIAL" else "ENROLLMENT"
    return {
        "record_id": f"SYNTH_{prefix}_RECORD_{record_number:03d}",
        "record_kind": kind,
        "provider_id": PROVIDER_GRAPH_SUBJECT,
        "credential_id": CREDENTIAL_ID,
        "enrollment_id": ENROLLMENT_ID,
        "subject_key": SUBJECT_KEY,
        "observed_at": observation_time,
        "issued_at": 6_000,
        "valid_from": 6_000,
        "valid_until": valid_until,
        "terminated_at": terminated_at,
        "status": status,
    }


def demo_input(case: str = "confirmed") -> dict[str, object]:
    """Build one canonical synthetic input vector for tests and operators."""

    observation_time = 7_000
    credential_record = _demo_record("CREDENTIAL", observation_time=observation_time)
    enrollment_record = _demo_record("ENROLLMENT", observation_time=observation_time)
    credential_records = [credential_record]
    enrollment_records = [enrollment_record]
    credential_complete = True
    enrollment_complete = True
    credential_nonmembership: list[str] = []
    enrollment_nonmembership: list[str] = []
    credential_end = 9_000
    enrollment_end = 9_000
    if case == "expired":
        credential_record["valid_until"] = 6_500
        credential_record["status"] = STATUS_EXPIRED
    elif case == "terminated":
        enrollment_record["terminated_at"] = 6_500
        enrollment_record["status"] = STATUS_TERMINATED
    elif case == "incomplete":
        enrollment_complete = False
    elif case == "absent":
        credential_records = []
        enrollment_records = []
        credential_nonmembership = [SUBJECT_KEY]
        enrollment_nonmembership = [SUBJECT_KEY]
    elif case == "conflict":
        credential_records = [credential_record, _demo_record("CREDENTIAL", record_number=2, observation_time=observation_time)]
    elif case == "stale":
        credential_end = 6_999
    elif case != "confirmed":
        raise ProviderTrustGraphError("demo:unknown-case")
    return {
        "schema": INPUT_SCHEMA,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "observation_time": observation_time,
        "sources": [
            _source_for_demo(SOURCE_CREDENTIAL_ID, SOURCE_CREDENTIAL_KIND, observation_time=observation_time, records=credential_records, complete=credential_complete, nonmembership=credential_nonmembership, end=credential_end),
            _source_for_demo(SOURCE_ENROLLMENT_ID, SOURCE_ENROLLMENT_KIND, observation_time=observation_time, records=enrollment_records, complete=enrollment_complete, nonmembership=enrollment_nonmembership, end=enrollment_end),
        ],
    }
