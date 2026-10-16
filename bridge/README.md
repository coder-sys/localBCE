# RightRail Off-Chain Bridge

This bridge is the active integration boundary selected after retiring proof
execution and chain settlement. It consumes the existing Rust adjudication
result, writes an append-only local journal, accepts synthetic redacted
remittance events, and produces deterministic reconciliation reports.

It does not import or execute the external RightRail SQLite owner, Lean worker,
UI, binaries, signers, or payment code. It cannot move money. Groth16 and STARK
remain disabled by `proof_execution_enabled: false`.

## Record an adjudication

Run the Rust adjudicator first, then record its result with an explicit amount
in integer cents:

```bash
python3 -m bridge.rightrail_offchain record-adjudication \
  --ledger state/rightrail_offchain_ledger.jsonl \
  --result rust-engine/adjudication_result.json \
  --owed-cents 100000 \
  --program synthetic-medicaid \
  --jurisdiction US-TEST
```

The command rejects results that contain a submitted transaction.

## Record a remittance

```bash
python3 -m bridge.rightrail_offchain record-remittance \
  --ledger state/rightrail_offchain_ledger.jsonl \
  --event path/to/synthetic_remittance.json
```

The input follows
`interfaces/rightrail_offchain_remittance_event_v1.schema.json`. Raw 835 files,
member IDs, provider IDs, credentials, and PHI are outside this boundary.

## Verify and reconcile

```bash
python3 -m bridge.rightrail_offchain verify \
  --ledger state/rightrail_offchain_ledger.jsonl

python3 -m bridge.rightrail_offchain reconcile \
  --ledger state/rightrail_offchain_ledger.jsonl \
  --output state/rightrail_reconciliation_report.json
```

The report is a read-only replay. It never repairs the journal or triggers a
payment, proof, signature, or transaction.
