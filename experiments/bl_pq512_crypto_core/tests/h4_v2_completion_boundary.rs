use bl_pq512_crypto_core::field::{Fp16, M31};
use bl_pq512_crypto_core::semantic_h4_bridge_gkr::{
    PublicBridgeInnerProductProof, SemanticH4BridgeGkrError,
    decode_public_bridge_inner_product_proof, encode_public_bridge_inner_product_proof,
};

fn fp(value: u32) -> Fp16 {
    Fp16::from_m31(M31::from_canonical(value).unwrap())
}

#[test]
fn bridge_inner_product_transport_is_canonical_and_roundtrips() {
    let proof = PublicBridgeInnerProductProof {
        rounds: vec![[fp(1), fp(2), fp(3)], [fp(5), fp(7), fp(11)]],
    };
    let encoded = encode_public_bridge_inner_product_proof(&proof).unwrap();
    assert_eq!(&encoded[..8], b"BLBIPV02");
    assert_eq!(
        decode_public_bridge_inner_product_proof(&encoded).unwrap(),
        proof
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        decode_public_bridge_inner_product_proof(&trailing),
        Err(SemanticH4BridgeGkrError::Encoding)
    );

    let mut reserved = encoded;
    reserved[16] = 1;
    assert_eq!(
        decode_public_bridge_inner_product_proof(&reserved),
        Err(SemanticH4BridgeGkrError::Encoding)
    );
}
