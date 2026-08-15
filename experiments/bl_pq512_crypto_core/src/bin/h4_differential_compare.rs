//! Compare the retained CPU/GPU-path H4 diagnostic dumps.
//!
//! This command is read-only. It never starts a prover, GPU process, or
//! coordinator. It implements the three-way decision rule for the evidence
//! that is actually present: points first, then the common source vector and
//! buffer metadata, then a common result label. If a required common artifact
//! is absent it reports that fact instead of inventing a classification.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PathDump {
    points: BTreeMap<String, Vec<(usize, String, String)>>,
    vectors: BTreeMap<String, Vec<(usize, String, String)>>,
    buffers: BTreeMap<usize, BTreeMap<String, String>>,
    results: BTreeMap<String, String>,
    declared_point_count: Option<usize>,
    declared_vector_count: Option<usize>,
    declared_buffer_count: Option<usize>,
    declared_result_count: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Fp16Vector {
    label: String,
    values: Vec<Vec<u8>>,
}

fn parse_indexed_field<'a>(key: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    let suffix = key.strip_prefix(prefix)?;
    let end = suffix.find(']')?;
    let index = suffix.get(..end)?.parse().ok()?;
    let field = suffix.get(end + 2..)?;
    Some((index, field))
}

fn parse_vector_field<'a>(key: &'a str) -> Option<(usize, Option<usize>, &'a str)> {
    let suffix = key.strip_prefix("vector[")?;
    let outer_end = suffix.find(']')?;
    let outer = suffix.get(..outer_end)?.parse().ok()?;
    let remainder = suffix.get(outer_end + 1..)?;
    if let Some(field) = remainder.strip_prefix('.') {
        return Some((outer, None, field));
    }
    let remainder = remainder.strip_prefix('[')?;
    let inner_end = remainder.find(']')?;
    let inner = remainder.get(..inner_end)?.parse().ok()?;
    let field = remainder.get(inner_end + 1..)?.strip_prefix('.')?;
    Some((outer, Some(inner), field))
}

fn read_path_dump(path: &Path) -> Result<PathDump, String> {
    let encoded = fs::read_to_string(path).map_err(|error| format!("read:{path:?}:{error}"))?;
    let mut point_fields = BTreeMap::<usize, BTreeMap<String, String>>::new();
    let mut vector_fields = BTreeMap::<usize, BTreeMap<String, String>>::new();
    let mut vector_item_fields = BTreeMap::<(usize, usize), BTreeMap<String, String>>::new();
    let mut dump = PathDump::default();
    let mut format_seen = false;
    for line in encoded.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed_line:{path:?}"))?;
        if key == "format" {
            if value != "BLH4DIFF01" {
                return Err(format!("format:{path:?}"));
            }
            format_seen = true;
            continue;
        }
        if key == "point_count" {
            dump.declared_point_count =
                Some(value.parse().map_err(|_| format!("point_count:{path:?}"))?);
            continue;
        }
        if key == "vector_count" {
            dump.declared_vector_count = Some(
                value
                    .parse()
                    .map_err(|_| format!("vector_count:{path:?}"))?,
            );
            continue;
        }
        if key == "buffer_count" {
            dump.declared_buffer_count = Some(
                value
                    .parse()
                    .map_err(|_| format!("buffer_count:{path:?}"))?,
            );
            continue;
        }
        if key == "result_count" {
            dump.declared_result_count = Some(
                value
                    .parse()
                    .map_err(|_| format!("result_count:{path:?}"))?,
            );
            continue;
        }
        if let Some((index, field)) = parse_indexed_field(key, "point[") {
            point_fields
                .entry(index)
                .or_default()
                .insert(field.to_owned(), value.to_owned());
            continue;
        }
        if let Some((index, item, field)) = parse_vector_field(key) {
            match item {
                Some(item) => vector_item_fields
                    .entry((index, item))
                    .or_default()
                    .insert(field.to_owned(), value.to_owned()),
                None => vector_fields
                    .entry(index)
                    .or_default()
                    .insert(field.to_owned(), value.to_owned()),
            };
            continue;
        }
        if let Some((index, field)) = parse_indexed_field(key, "buffer[") {
            dump.buffers
                .entry(index)
                .or_default()
                .insert(field.to_owned(), value.to_owned());
            continue;
        }
        if let Some((index, field)) = parse_indexed_field(key, "result[") {
            if field == "label" {
                // Store the result label under its ordinal temporarily. The
                // encoding line below is reconciled after the full parse.
                dump.results.insert(format!("#{index}"), value.to_owned());
            } else if field == "encoding" {
                dump.results
                    .insert(format!("#{index}:encoding"), value.to_owned());
            }
        }
    }

    if !format_seen {
        return Err(format!("format_missing:{path:?}"));
    }
    if dump.declared_point_count != Some(point_fields.len()) {
        return Err(format!(
            "point_count_mismatch:{path:?}:declared={:?}:observed={}",
            dump.declared_point_count,
            point_fields.len()
        ));
    }
    if point_fields
        .keys()
        .copied()
        .enumerate()
        .any(|(expected, observed)| expected != observed)
    {
        return Err(format!("point_ordinals_not_contiguous:{path:?}"));
    }

    let mut points_by_label = BTreeMap::<String, Vec<(usize, String, String)>>::new();
    for (index, fields) in point_fields {
        let label = fields
            .get("label")
            .ok_or_else(|| format!("point_label:{path:?}:{index}"))?;
        let encoding = fields
            .get("encoding")
            .ok_or_else(|| format!("point_encoding:{path:?}:{index}"))?;
        let (vector_label, coordinate) = label
            .rsplit_once('[')
            .and_then(|(prefix, suffix)| suffix.strip_suffix(']').map(|value| (prefix, value)))
            .ok_or_else(|| format!("point_label_shape:{path:?}:{label}"))?;
        let coordinate = coordinate
            .parse::<usize>()
            .map_err(|_| format!("point_index:{path:?}:{label}"))?;
        points_by_label
            .entry(vector_label.to_owned())
            .or_default()
            .push((coordinate, label.clone(), encoding.clone()));
    }
    for values in points_by_label.values_mut() {
        values.sort_by_key(|(index, _, _)| *index);
    }
    dump.points = points_by_label;

    if dump.declared_vector_count != Some(vector_fields.len()) {
        return Err(format!(
            "vector_count_mismatch:{path:?}:declared={:?}:observed={}",
            dump.declared_vector_count,
            vector_fields.len()
        ));
    }
    if vector_fields
        .keys()
        .copied()
        .enumerate()
        .any(|(expected, observed)| expected != observed)
    {
        return Err(format!("vector_ordinals_not_contiguous:{path:?}"));
    }
    let mut vectors_by_label = BTreeMap::<String, Vec<(usize, String, String)>>::new();
    for (index, fields) in vector_fields {
        let label = fields
            .get("label")
            .ok_or_else(|| format!("vector_label:{path:?}:{index}"))?;
        let count = fields
            .get("count")
            .ok_or_else(|| format!("vector_count_field:{path:?}:{index}"))?
            .parse::<usize>()
            .map_err(|_| format!("vector_count_field:{path:?}:{index}"))?;
        let mut values = Vec::with_capacity(count);
        for item in 0..count {
            let fields = vector_item_fields
                .get(&(index, item))
                .ok_or_else(|| format!("vector_item_missing:{path:?}:{index}:{item}"))?;
            let item_label = fields
                .get("label")
                .ok_or_else(|| format!("vector_item_label:{path:?}:{index}:{item}"))?;
            let encoding = fields
                .get("encoding")
                .ok_or_else(|| format!("vector_item_encoding:{path:?}:{index}:{item}"))?;
            values.push((item, item_label.clone(), encoding.clone()));
        }
        if vector_item_fields
            .keys()
            .any(|(outer, item)| *outer == index && *item >= count)
        {
            return Err(format!("vector_item_count_mismatch:{path:?}:{index}"));
        }
        if vectors_by_label.insert(label.clone(), values).is_some() {
            return Err(format!("duplicate_vector_label:{path:?}:{label}"));
        }
    }
    dump.vectors = vectors_by_label;

    for (index, fields) in &dump.buffers {
        for required in [
            "label",
            "base_offset_bytes",
            "element_stride_bytes",
            "element_count",
            "index_formula",
        ] {
            if !fields.contains_key(required) {
                return Err(format!("buffer_field_missing:{path:?}:{index}:{required}"));
            }
        }
    }
    if dump.declared_buffer_count != Some(dump.buffers.len()) {
        return Err(format!(
            "buffer_count_mismatch:{path:?}:declared={:?}:observed={}",
            dump.declared_buffer_count,
            dump.buffers.len()
        ));
    }

    let mut result_values = BTreeMap::new();
    for (key, label) in dump.results.clone() {
        if let Some(index) = key
            .strip_prefix('#')
            .and_then(|value| value.parse::<usize>().ok())
        {
            if let Some(encoding) = dump.results.get(&format!("#{index}:encoding")) {
                if result_values
                    .insert(label.clone(), encoding.clone())
                    .is_some()
                {
                    return Err(format!("duplicate_result_label:{path:?}:{label}"));
                }
            }
        }
    }
    dump.results = result_values;
    if dump.declared_result_count != Some(dump.results.len()) {
        return Err(format!(
            "result_count_mismatch:{path:?}:declared={:?}:observed={}",
            dump.declared_result_count,
            dump.results.len()
        ));
    }
    Ok(dump)
}

fn read_fp16_vector(path: &Path) -> Result<Fp16Vector, String> {
    let encoded = fs::read(path).map_err(|error| format!("read:{path:?}:{error}"))?;
    if encoded.len() < 24 || encoded.get(..8) != Some(b"BLH4FP01") {
        return Err(format!("vector_header:{path:?}"));
    }
    if encoded[10..16] != [0_u8; 6] {
        return Err(format!("vector_reserved:{path:?}"));
    }
    let label_length = usize::from(u16::from_be_bytes(
        encoded[8..10]
            .try_into()
            .map_err(|_| "vector_label_length")?,
    ));
    let count = usize::try_from(u64::from_be_bytes(
        encoded[16..24]
            .try_into()
            .map_err(|_| "vector_count_width")?,
    ))
    .map_err(|_| "vector_count_host")?;
    let label_end = 24_usize
        .checked_add(label_length)
        .ok_or("vector_label_overflow")?;
    let data_bytes = count.checked_mul(64).ok_or("vector_data_overflow")?;
    if label_end.checked_add(data_bytes) != Some(encoded.len()) {
        return Err(format!("vector_length:{path:?}"));
    }
    let label = String::from_utf8(encoded[24..label_end].to_vec())
        .map_err(|_| format!("vector_label_utf8:{path:?}"))?;
    let mut values = Vec::with_capacity(count);
    for chunk in encoded[label_end..].chunks_exact(64) {
        values.push(chunk.to_vec());
    }
    Ok(Fp16Vector { label, values })
}

fn print_points_difference(native: &PathDump, answer: &PathDump) -> Result<bool, String> {
    for label in [
        "booleanity_group_point",
        "padding_sumcheck_point",
        "row_challenges",
    ] {
        let native_point = native
            .points
            .get(label)
            .ok_or_else(|| format!("differential_dumps_missing:native {label}"))?;
        let answer_point = answer
            .points
            .get(label)
            .ok_or_else(|| format!("differential_dumps_missing:answer {label}"))?;
        if native_point.len() != answer_point.len() {
            println!("DIFFERENTIAL_POINTS_DIFFER");
            println!("point_label={label}");
            println!(
                "point_count_native={} point_count_answer={}",
                native_point.len(),
                answer_point.len()
            );
            return Ok(false);
        }
        for (native_value, answer_value) in native_point.iter().zip(answer_point) {
            if native_value.2 != answer_value.2 {
                println!("DIFFERENTIAL_POINTS_DIFFER");
                println!("point_label={label}");
                println!("point_index={}", native_value.0);
                println!("native_label={}", native_value.1);
                println!("answer_label={}", answer_value.1);
                println!("native_encoding={}", native_value.2);
                println!("answer_encoding={}", answer_value.2);
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn compare_vectors(native: &Fp16Vector, answer: &Fp16Vector) -> bool {
    native.label == answer.label && native.values == answer.values
}

fn buffers_by_label(dump: &PathDump) -> BTreeMap<String, BTreeMap<String, String>> {
    dump.buffers
        .values()
        .filter_map(|fields| {
            fields
                .get("label")
                .map(|label| (label.clone(), fields.clone()))
        })
        .collect()
}

fn compare_dump_vectors(native: &PathDump, answer: &PathDump) -> Result<bool, String> {
    if native.vectors.keys().ne(answer.vectors.keys()) {
        println!("DIFFERENTIAL_COEFFICIENTS_DIFFER");
        println!(
            "native_vector_labels={:?}",
            native.vectors.keys().collect::<Vec<_>>()
        );
        println!(
            "answer_vector_labels={:?}",
            answer.vectors.keys().collect::<Vec<_>>()
        );
        return Ok(false);
    }
    for label in native.vectors.keys() {
        let left = &native.vectors[label];
        let right = &answer.vectors[label];
        if left.len() != right.len() {
            println!("DIFFERENTIAL_COEFFICIENTS_DIFFER");
            println!("vector_label={label}");
            println!(
                "native_vector_count={} answer_vector_count={}",
                left.len(),
                right.len()
            );
            return Ok(false);
        }
        for (native_value, answer_value) in left.iter().zip(right) {
            if native_value != answer_value {
                println!("DIFFERENTIAL_COEFFICIENTS_DIFFER");
                println!("vector_label={label}");
                println!("vector_index={}", native_value.0);
                println!("native_label={}", native_value.1);
                println!("answer_label={}", answer_value.1);
                println!("native_encoding={}", native_value.2);
                println!("answer_encoding={}", answer_value.2);
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn run(capture: &Path) -> Result<(), String> {
    if !capture.is_absolute() {
        return Err("capture_path_not_absolute".to_owned());
    }
    let native = read_path_dump(&capture.join("h4-native-path.txt"))?;
    let answer = read_path_dump(&capture.join("h4-answer-path.txt"))?;
    if !print_points_difference(&native, &answer)? {
        return Ok(());
    }

    if !compare_dump_vectors(&native, &answer)? {
        return Ok(());
    }

    let native_vector = read_fp16_vector(&capture.join("h4-native-source-coefficients.bin"))?;
    let answer_vector = read_fp16_vector(&capture.join("h4-answer-source-coefficients.bin"))?;
    if !compare_vectors(&native_vector, &answer_vector) {
        println!("DIFFERENTIAL_COEFFICIENTS_DIFFER");
        println!("native_vector_label={}", native_vector.label);
        println!("answer_vector_label={}", answer_vector.label);
        println!("native_vector_count={}", native_vector.values.len());
        println!("answer_vector_count={}", answer_vector.values.len());
        if let Some((index, (left, right))) = native_vector
            .values
            .iter()
            .zip(&answer_vector.values)
            .enumerate()
            .find(|(_, (left, right))| *left != *right)
        {
            println!("first_vector_mismatch_index={index}");
            println!("native_encoding={}", hex(left));
            println!("answer_encoding={}", hex(right));
        }
        return Ok(());
    }
    let native_buffers = buffers_by_label(&native);
    let answer_buffers = buffers_by_label(&answer);
    let common_buffers = native_buffers
        .keys()
        .filter(|label| answer_buffers.contains_key(*label))
        .cloned()
        .collect::<Vec<_>>();
    if common_buffers.is_empty() {
        return Err(
            "differential_dumps_unpaired_buffer:native and answer have no common buffer label"
                .to_owned(),
        );
    }
    for label in common_buffers {
        if native_buffers[&label] != answer_buffers[&label] {
            println!("DIFFERENTIAL_COEFFICIENTS_DIFFER");
            println!("buffer_label={label}");
            for field in [
                "base_offset_bytes",
                "element_stride_bytes",
                "element_count",
                "index_formula",
            ] {
                if native_buffers[&label].get(field) != answer_buffers[&label].get(field) {
                    println!(
                        "buffer_field={} native={:?} answer={:?}",
                        field,
                        native_buffers[&label].get(field),
                        answer_buffers[&label].get(field)
                    );
                }
            }
            return Ok(());
        }
    }

    let common_results = native
        .results
        .keys()
        .filter(|label| answer.results.contains_key(*label))
        .cloned()
        .collect::<Vec<_>>();
    if common_results.is_empty() {
        return Err(
            "differential_dumps_unpaired_result:native and answer have no common result label"
                .to_owned(),
        );
    }
    for label in common_results {
        if native.results[&label] != answer.results[&label] {
            println!("DIFFERENTIAL_EVALUATOR_DIFFER");
            println!("result_label={label}");
            println!("native_encoding={}", native.results[&label]);
            println!("answer_encoding={}", answer.results[&label]);
            return Ok(());
        }
    }
    println!("DIFFERENTIAL_EVALUATOR_MATCHES");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<_>>();
    if arguments.len() != 2 {
        eprintln!("ERR usage: h4_differential_compare <capture-dir>");
        return ExitCode::from(2);
    }
    match run(&PathBuf::from(&arguments[1])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(2)
        }
    }
}
