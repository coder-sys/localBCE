use std::array;

use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::simd::column::BaseColumn;

#[test]
fn into_cpu_vec_preserves_values_and_allocator_layout() {
    let values: [BaseField; 30] = array::from_fn(BaseField::from);
    let result = values.into_iter().collect::<BaseColumn>().into_cpu_vec();

    assert_eq!(result, values);
}
