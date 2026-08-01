//! Bounded-memory OODS claims and exact DEEP degree planning.

use core::fmt;

use alloc::collections::BTreeMap;
use alloc::{format, string::String, vec::Vec};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::circle_fri::{
    CircleFriError, bit_reverse_index, canonic_circle_point, conjugate_pair_zeroifier,
};
use crate::deep_quotient::{DeepQuotientError, DomainOodsClaims};
use crate::disk_air::{DiskAirError, DiskAirMainTraceOracle};
use crate::disk_composition::{DiskAirCompositionOracle, DiskCompositionError};
use crate::disk_fft::{
    DiskFftError, evaluate_extension_coefficient_file_at_point_in_place,
    interpolate_extension_circle_file_in_place,
};
use crate::disk_logup::{DiskAirLogupOracle, DiskLogupError};
use crate::field::{FP16_ENCODED_LENGTH, Fp16, M31, M31_MODULUS, batch_inverse_fp16};
use crate::oods::CirclePoint;

const DEEP_BLOCK_ROWS: usize = 1 << 12;

#[derive(Clone, Debug)]
pub enum DiskOriginalColumn {
    M31(PathBuf),
    Fp16(PathBuf),
}

#[derive(Clone, Debug)]
pub struct DiskDeepDomainPlan {
    pub log_size: u8,
    pub columns: Vec<DiskOriginalColumn>,
    pub degree_bound: usize,
}

#[derive(Clone, Debug)]
pub struct DiskDeepQuotientPlan {
    pub query: CirclePoint,
    pub claims: Vec<DomainOodsClaims>,
    /// Descending, matching the FRI attachment order.
    pub domains: Vec<DiskDeepDomainPlan>,
}

#[derive(Debug)]
pub enum DiskDeepError {
    Circle(crate::circle_fft::CircleFftError),
    CircleFri(CircleFriError),
    Deep(DeepQuotientError),
    DiskAir(DiskAirError),
    DiskComposition(DiskCompositionError),
    DiskFft(DiskFftError),
    DiskLogup(DiskLogupError),
    Decode(crate::field::DecodeError),
    Field(crate::field::FieldError),
    Io(std::io::ErrorKind),
    Parent,
    Shape,
    Overflow,
    DegreeBound { log_size: u8, used: usize },
}

macro_rules! convert_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for DiskDeepError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

convert_error!(crate::circle_fft::CircleFftError, Circle);
convert_error!(CircleFriError, CircleFri);
convert_error!(DeepQuotientError, Deep);
convert_error!(DiskAirError, DiskAir);
convert_error!(DiskCompositionError, DiskComposition);
convert_error!(DiskFftError, DiskFft);
convert_error!(DiskLogupError, DiskLogup);
convert_error!(crate::field::DecodeError, Decode);
convert_error!(crate::field::FieldError, Field);

impl From<std::io::Error> for DiskDeepError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for DiskDeepError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk DEEP error: {self:?}")
    }
}

impl core::error::Error for DiskDeepError {}

pub fn build_disk_deep_quotient_plan(
    main: &DiskAirMainTraceOracle,
    logup: &DiskAirLogupOracle,
    composition: &DiskAirCompositionOracle,
    query: CirclePoint,
    scratch_parent: &Path,
    build_nonce: &[u8; 32],
) -> Result<DiskDeepQuotientPlan, DiskDeepError> {
    if !scratch_parent.is_absolute()
        || !scratch_parent.is_dir()
        || query.x.square().add(query.y.square()) != Fp16::ONE
        || (query.x.is_in_fp8_subfield() && query.y.is_in_fp8_subfield())
        || main.program_binary_commitment != composition.program_binary_commitment
        || main.source_program_commitment != composition.source_program_commitment
    {
        return Err(DiskDeepError::Parent);
    }
    let groups = grouped_columns(main, logup, composition)?;
    let directory = scratch_parent.join(temp_name(build_nonce));
    fs::create_dir(&directory)?;
    let result = build_plan_in_directory(groups, query, &directory);
    let cleanup = fs::remove_dir_all(&directory);
    match (result, cleanup) {
        (Ok(plan), Ok(())) => Ok(plan),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn grouped_columns(
    main: &DiskAirMainTraceOracle,
    logup: &DiskAirLogupOracle,
    composition: &DiskAirCompositionOracle,
) -> Result<BTreeMap<u8, Vec<DiskOriginalColumn>>, DiskDeepError> {
    let mut groups = BTreeMap::<u8, Vec<DiskOriginalColumn>>::new();
    for table in &main.tables {
        if table.column_files.len() != table.committed_column_indices.len() {
            return Err(DiskDeepError::Shape);
        }
        groups.entry(table.evaluation_log_size).or_default().extend(
            table
                .column_files
                .iter()
                .cloned()
                .map(DiskOriginalColumn::M31),
        );
    }
    for interaction in &logup.interactions {
        groups
            .entry(interaction.evaluation_log_size)
            .or_default()
            .extend(
                interaction
                    .masked_column_files
                    .iter()
                    .cloned()
                    .map(DiskOriginalColumn::Fp16),
            );
    }
    for table in &composition.tables {
        groups.entry(table.evaluation_log_size).or_default().extend(
            table
                .component_files
                .iter()
                .cloned()
                .map(DiskOriginalColumn::Fp16),
        );
    }
    if groups.is_empty() || groups.values().any(Vec::is_empty) {
        return Err(DiskDeepError::Shape);
    }
    Ok(groups)
}

fn build_plan_in_directory(
    groups: BTreeMap<u8, Vec<DiskOriginalColumn>>,
    query: CirclePoint,
    directory: &Path,
) -> Result<DiskDeepQuotientPlan, DiskDeepError> {
    let conjugate = CirclePoint {
        x: query.x.conjugate(),
        y: query.y.conjugate(),
    };
    let mut claims = Vec::with_capacity(groups.len());
    let mut ascending_plans = Vec::with_capacity(groups.len());
    for (log_size, columns) in groups {
        let rows = 1_usize << log_size;
        for column in &columns {
            validate_source(column, rows)?;
        }
        let mut values = Vec::with_capacity(columns.len());
        let mut conjugate_values = Vec::with_capacity(columns.len());
        let mut maximum_used = 0usize;
        for (column_index, source) in columns.iter().enumerate() {
            let coefficients =
                directory.join(format!("coeff-l{log_size:02}-c{column_index:08x}.fp16"));
            materialize_fp16(source, rows, &coefficients)?;
            interpolate_extension_circle_file_in_place(&coefficients, log_size)?;
            maximum_used = maximum_used.max(last_nonzero(&coefficients, rows)?);
            let query_file =
                directory.join(format!("query-l{log_size:02}-c{column_index:08x}.fp16"));
            let conjugate_file =
                directory.join(format!("conjugate-l{log_size:02}-c{column_index:08x}.fp16"));
            fs::copy(&coefficients, &query_file)?;
            fs::copy(&coefficients, &conjugate_file)?;
            values.push(evaluate_extension_coefficient_file_at_point_in_place(
                &query_file,
                log_size,
                query,
            )?);
            conjugate_values.push(evaluate_extension_coefficient_file_at_point_in_place(
                &conjugate_file,
                log_size,
                conjugate,
            )?);
            fs::remove_file(coefficients)?;
            fs::remove_file(query_file)?;
            fs::remove_file(conjugate_file)?;
        }
        for (column_index, source) in columns.iter().enumerate() {
            let quotient =
                directory.join(format!("quotient-l{log_size:02}-c{column_index:08x}.fp16"));
            write_quotient_evaluations(
                source,
                log_size,
                query,
                values[column_index],
                conjugate_values[column_index],
                &quotient,
            )?;
            interpolate_extension_circle_file_in_place(&quotient, log_size)?;
            maximum_used = maximum_used.max(last_nonzero(&quotient, rows)?);
            fs::remove_file(quotient)?;
        }
        let degree_bound = maximum_used.max(2).next_power_of_two();
        if degree_bound >= rows {
            return Err(DiskDeepError::DegreeBound {
                log_size,
                used: maximum_used,
            });
        }
        claims.push(DomainOodsClaims {
            log_size,
            values,
            conjugate_values,
        });
        ascending_plans.push(DiskDeepDomainPlan {
            log_size,
            columns,
            degree_bound,
        });
    }
    ascending_plans.reverse();
    Ok(DiskDeepQuotientPlan {
        query,
        claims,
        domains: ascending_plans,
    })
}

fn write_quotient_evaluations(
    source: &DiskOriginalColumn,
    log_size: u8,
    query: CirclePoint,
    claim: Fp16,
    conjugate_claim: Fp16,
    output: &Path,
) -> Result<(), DiskDeepError> {
    let conjugate = CirclePoint {
        x: query.x.conjugate(),
        y: query.y.conjugate(),
    };
    let (use_y, query_coordinate, conjugate_coordinate) = if query.y != conjugate.y {
        (true, query.y, conjugate.y)
    } else if query.x != conjugate.x {
        (false, query.x, conjugate.x)
    } else {
        return Err(DiskDeepError::Shape);
    };
    let scale = conjugate_coordinate.sub(query_coordinate);
    let slope = conjugate_claim.sub(claim);
    let intercept = claim.mul(scale).sub(slope.mul(query_coordinate));
    let rows = 1_usize << log_size;
    let mut source = SourceReader::new(source)?;
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    for start in (0..rows).step_by(DEEP_BLOCK_ROWS) {
        let count = DEEP_BLOCK_ROWS.min(rows - start);
        let mut points = Vec::with_capacity(count);
        let mut zeroifiers = Vec::with_capacity(count);
        for fft_index in start..start + count {
            let point = canonic_circle_point(log_size, bit_reverse_index(fft_index, log_size)?)?;
            zeroifiers.push(conjugate_pair_zeroifier(point, query)?);
            points.push(point);
        }
        let inverses = batch_inverse_fp16(&zeroifiers).map_err(|_| DiskDeepError::Shape)?;
        for (point, inverse) in points.into_iter().zip(inverses) {
            let original = source.read()?;
            let coordinate = Fp16::from_m31(if use_y { point.y } else { point.x });
            let claim_line = slope.mul(coordinate).add(intercept);
            let quotient = scale.mul(original).sub(claim_line).mul(inverse);
            output.write_all(&quotient.encode())?;
        }
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

enum SourceReader {
    M31(BufReader<File>),
    Fp16(BufReader<File>),
}

impl SourceReader {
    fn new(source: &DiskOriginalColumn) -> Result<Self, DiskDeepError> {
        Ok(match source {
            DiskOriginalColumn::M31(path) => Self::M31(BufReader::new(File::open(path)?)),
            DiskOriginalColumn::Fp16(path) => Self::Fp16(BufReader::new(File::open(path)?)),
        })
    }

    fn read(&mut self) -> Result<Fp16, DiskDeepError> {
        match self {
            Self::M31(reader) => {
                let mut encoded = [0_u8; 4];
                reader.read_exact(&mut encoded)?;
                let value = u32::from_be_bytes(encoded);
                if value >= M31_MODULUS {
                    return Err(DiskDeepError::Shape);
                }
                Ok(Fp16::from_m31(M31::from_canonical(value)?))
            }
            Self::Fp16(reader) => {
                let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
                reader.read_exact(&mut encoded)?;
                Ok(Fp16::decode(&encoded)?)
            }
        }
    }
}

fn validate_source(source: &DiskOriginalColumn, rows: usize) -> Result<(), DiskDeepError> {
    let scalar_bytes = match source {
        DiskOriginalColumn::M31(_) => 4_u64,
        DiskOriginalColumn::Fp16(_) => FP16_ENCODED_LENGTH as u64,
    };
    let path = match source {
        DiskOriginalColumn::M31(path) | DiskOriginalColumn::Fp16(path) => path,
    };
    let expected = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(scalar_bytes))
        .ok_or(DiskDeepError::Overflow)?;
    if !path.is_absolute() || fs::metadata(path)?.len() != expected {
        return Err(DiskDeepError::Shape);
    }
    Ok(())
}

fn materialize_fp16(
    source: &DiskOriginalColumn,
    rows: usize,
    output: &Path,
) -> Result<(), DiskDeepError> {
    let mut source = SourceReader::new(source)?;
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    for _ in 0..rows {
        output.write_all(&source.read()?.encode())?;
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn last_nonzero(path: &Path, rows: usize) -> Result<usize, DiskDeepError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut last = 0usize;
    for row in 0..rows {
        let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
        reader.read_exact(&mut encoded)?;
        if !Fp16::decode(&encoded)?.is_zero() {
            last = row + 1;
        }
    }
    Ok(last)
}

fn temp_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-disk-deep-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}
