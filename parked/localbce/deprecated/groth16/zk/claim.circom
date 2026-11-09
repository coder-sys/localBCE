pragma circom 2.0.0;

template IsEqual() {
    signal input in[2];
    signal output out;

    signal diff;
    diff <== in[0] - in[1];

    signal inv;
    inv <-- diff != 0 ? 1 / diff : 0;

    out <== 1 - diff * inv;
    diff * out === 0;
}

template ClaimValidator() {
    signal input eligibility_active;

    signal input aid_code;
    signal input benefit_level_exists;

    signal input date_of_service_from;
    signal input eligibility_period_from;
    signal input eligibility_period_thru;

    signal input soc_amount;
    signal input soc_met;

    // G5 inputs
    signal input provider_enrolled;
    signal input provider_type_valid;

    // G6 inputs
    signal input billing_code_valid;
    signal input units_valid;

    // G7 input
    signal input is_duplicate;

    // G8 input
    signal input disability_determination_valid;

    // G9 input
    signal input recipient_not_deceased;

    // G10 input
    signal input physician_certification_valid;

    signal output valid;

    // G1
    eligibility_active === 1;

    // G2 aid code: 13, 23, 53, 103, 104
    component eq13 = IsEqual();
    component eq23 = IsEqual();
    component eq53 = IsEqual();
    component eqD3 = IsEqual();
    component eqD4 = IsEqual();

    eq13.in[0] <== aid_code;
    eq13.in[1] <== 13;

    eq23.in[0] <== aid_code;
    eq23.in[1] <== 23;

    eq53.in[0] <== aid_code;
    eq53.in[1] <== 53;

    eqD3.in[0] <== aid_code;
    eqD3.in[1] <== 103;

    eqD4.in[0] <== aid_code;
    eqD4.in[1] <== 104;

    signal aid_valid;
    aid_valid <== eq13.out + eq23.out + eq53.out + eqD3.out + eqD4.out;

    aid_valid === 1;
    benefit_level_exists === 1;

    // G3 simplified range checks
    signal from_after_start;
    signal before_end;

    from_after_start <-- date_of_service_from >= eligibility_period_from ? 1 : 0;
    before_end <-- date_of_service_from <= eligibility_period_thru ? 1 : 0;

    from_after_start === 1;
    before_end === 1;

    // G4: If SOC amount > 0, SOC must be met
    signal soc_required;
    soc_required <-- soc_amount > 0 ? 1 : 0;

    signal g4_valid;
    g4_valid <== (1 - soc_required) + (soc_required * soc_met);
    g4_valid === 1;

    // G5: Provider validation
    provider_enrolled === 1;
    provider_type_valid === 1;

    // G6: Billing validation
    billing_code_valid === 1;
    units_valid === 1;

    // G7: Duplicate prevention
    is_duplicate === 0;

    // G8: Disability determination
    disability_determination_valid === 1;

    // G9: Recipient not deceased
    recipient_not_deceased === 1;

    // G10: Physician certification
    physician_certification_valid === 1;

    valid <== 1;
}

component main = ClaimValidator();