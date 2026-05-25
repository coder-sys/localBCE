# Safe Refactor Queue

## Priority 1
Move config values into config.json

## Priority 2
Add unit tests for denial_reason()

## Priority 3
Rename Counter.sol to ClaimsRegistry.sol safely

## Priority 4
Add deployment.json generation after forge deploy

## Priority 5
Add structured logging around proof generation

## Priority 6
Create typed Rust structs for adjudication_result.json

## Priority 7
Add integration test for approved claim flow

## Priority 8
Create docs for redeploy workflow

## DO NOT
- change claim.circom without explicit instruction
- activate rules_v9.json
- migrate away from Groth16
- rewrite architecture
- remove denial_reason()
