# Safe Refactor Queue

## Priority 1 - DONE
Move config values into config.json

## Priority 2 - DONE
Add unit tests for denial_reason()

## Priority 3 - DONE
Rename Counter.sol to ClaimsRegistry.sol safely

## Priority 4 - DONE
Add deployment.json generation after forge deploy

## Priority 5 - DONE
Add structured logging around proof generation

## Priority 6 - DONE
Create typed Rust structs for adjudication_result.json

## Priority 7 - DONE
Add integration test for approved claim flow

## Priority 8 - DONE
Create docs for redeploy workflow

## DO NOT
- change claim.circom without explicit instruction
- activate rules_v9.json
- migrate away from Groth16
- rewrite architecture
- remove denial_reason()
