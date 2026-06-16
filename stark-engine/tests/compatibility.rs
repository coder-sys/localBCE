use stark_engine::{ActiveClaimToStarkBridge, MappingClass};

#[test]
fn imported_winterfell_stark_fields_are_all_classified() {
    let mappings = ActiveClaimToStarkBridge::field_mappings();

    assert_eq!(
        mappings.len(),
        ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len()
    );

    for expected_field in ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS {
        assert!(
            mappings
                .iter()
                .any(|mapping| mapping.imported_stark_field == expected_field),
            "missing imported STARK field mapping for {expected_field}"
        );
    }
}

#[test]
fn imported_winterfell_mapping_classes_match_phase_5a() {
    let mappings = ActiveClaimToStarkBridge::field_mappings();

    assert_eq!(
        mappings
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Direct)
            .count(),
        3
    );
    assert_eq!(
        mappings
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Partial)
            .count(),
        4
    );
    assert_eq!(
        mappings
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Unmapped)
            .count(),
        4
    );
}

#[test]
fn direct_mappings_are_the_only_safe_initial_bridge_fields() {
    let direct_fields: Vec<&str> = ActiveClaimToStarkBridge::direct_mappings()
        .iter()
        .map(|mapping| mapping.imported_stark_field)
        .collect();

    assert_eq!(
        direct_fields,
        vec!["eligibility_active", "provider_enrolled", "duplicate_flag"]
    );
}

#[test]
fn direct_mappings_point_to_existing_active_rust_sources() {
    for mapping in ActiveClaimToStarkBridge::direct_mappings() {
        let source = mapping
            .active_rust_source
            .expect("direct mapping must name an active Rust source field");

        assert!(
            ActiveClaimToStarkBridge::ACTIVE_RUST_FIELDS.contains(&source),
            "direct mapping source field is not in active Rust model: {source}"
        );
    }
}
