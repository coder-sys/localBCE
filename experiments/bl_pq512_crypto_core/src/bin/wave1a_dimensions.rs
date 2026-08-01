use bl_pq512_crypto_core::wave1a_dimensions::{
    COMMITMENTS, CONSTRAINTS, LOOKUP_MESSAGE_WIDTH_ACROSS_TABLES, MAXIMUM_CONSTRAINT_DEGREE,
    RECORDS, TABLES, TRACE_COLUMNS_ACROSS_TABLES,
};

fn main() {
    println!(
        "profile_id\ttables\tcommitments\tlogical_rows\tpadded_rows\ttrace_columns\tconstraints\tmaximum_degree\tlookup_width\tpadded_cells\td_eff_upper_bound\tprogram_commitment_sha3_512"
    );
    for record in RECORDS {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            record.profile.profile_id(),
            TABLES,
            COMMITMENTS,
            record.logical_rows,
            record.padded_rows,
            TRACE_COLUMNS_ACROSS_TABLES,
            CONSTRAINTS,
            MAXIMUM_CONSTRAINT_DEGREE,
            LOOKUP_MESSAGE_WIDTH_ACROSS_TABLES,
            record.padded_cells,
            record.d_eff_upper_bound,
            record.program_commitment_sha3_512_hex,
        );
    }
}
