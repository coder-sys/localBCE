#!/usr/bin/env bash
set -euo pipefail

# Generated Claude web expansion batches.
# Run from gov-rules-kg-prototype with .venv activated.

# Batch 1: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs earned_income_tax_credit,social_security,ssi,tanf,unemployment_insurance --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 2: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs appeals,audits,due_process,fraud_abuse,penalties --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 3: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs fafsa,pell_grants,state_aid,student_loans,veterans_education_benefits --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 4: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs emergency_food_assistance,school_meals,snap,wic,aca_marketplace --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 5: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs chip,disability_ssi_health_eligibility,medicaid,medicare,veterans_health_benefits --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 6: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs homelessness_assistance,liheap,public_housing,rental_assistance,section_8_housing_choice_voucher --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 7: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs asylum,identity_verification,naturalization,visas,work_authorization --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 8: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs building_permits,business_licenses,driver_licenses,environmental_permits,professional_licenses --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 9: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs contract_awards,federal_grants,reporting_compliance,state_grants,vendor_eligibility --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 10: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs credits_refunds,federal_income_tax,payroll_tax,property_tax,sales_tax --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 11: 25 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs state_income_tax --jurisdictions federal --source-types regulation --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 12: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs earned_income_tax_credit,social_security,ssi,tanf,unemployment_insurance --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 13: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs appeals,audits,due_process,fraud_abuse,penalties --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 14: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs fafsa,pell_grants,state_aid,student_loans,veterans_education_benefits --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 15: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs emergency_food_assistance,school_meals,snap,wic,aca_marketplace --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 16: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs chip,disability_ssi_health_eligibility,medicaid,medicare,veterans_health_benefits --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 17: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs homelessness_assistance,liheap,public_housing,rental_assistance,section_8_housing_choice_voucher --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 18: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs asylum,identity_verification,naturalization,visas,work_authorization --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 19: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs building_permits,business_licenses,driver_licenses,environmental_permits,professional_licenses --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 20: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs contract_awards,federal_grants,reporting_compliance,state_grants,vendor_eligibility --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 21: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs credits_refunds,federal_income_tax,payroll_tax,property_tax,sales_tax --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 22: 25 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs state_income_tax --jurisdictions federal --source-types statute --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 23: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs earned_income_tax_credit,social_security,ssi,tanf,unemployment_insurance --jurisdictions federal --source-types agency_guidance --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 24: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs appeals,audits,due_process,fraud_abuse,penalties --jurisdictions federal --source-types agency_guidance --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1

# Batch 25: 125 candidate slots
python -m gov_rules_kg.main claude-web-research --ai-provider claude --claude-model claude-sonnet-4-6 --programs fafsa,pell_grants,state_aid,student_loans,veterans_education_benefits --jurisdictions federal --source-types agency_guidance --batch-size 5 --max-candidates-per-branch 25 --max-uses 10 --timeout-seconds 300 --retries 1
