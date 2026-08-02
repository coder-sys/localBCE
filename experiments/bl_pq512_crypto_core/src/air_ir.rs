//! Bounded binary parser and independent evaluator for the Wave 1A AIR IR.
//!
//! The transport is intentionally small and dependency-free: it binds the
//! human-auditable Python JSON program commitment, then carries the same typed
//! expressions, lookup multisets, traces, and public inputs for independent
//! evaluation in this `no_std` crate.

use core::fmt;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::field::{Fp16, M31};

/// Exact binary transport magic.
pub const AIR_BINARY_MAGIC: &[u8; 8] = b"BLPQAIR1";
/// Verifier-visible program-only transport magic.
pub const AIR_PROGRAM_MAGIC: &[u8; 8] = b"BLPQARP1";
/// Exact binary transport version.
pub const AIR_BINARY_VERSION: u16 = 1;
/// Binary transport version supporting canonical compact fixed columns.
pub const AIR_BINARY_COMPACT_FIXED_VERSION: u16 = 2;
/// Maximum accepted transport length.
pub const MAX_AIR_BINARY_BYTES: usize = 512 * 1024 * 1024;
/// Commitment domain for the complete binary execution object.
pub const AIR_BINARY_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/AIR-BINARY-IR/v1\0";
/// Commitment domain for verifier-visible program metadata.
pub const AIR_PROGRAM_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/AIR-PROGRAM-IR/v1\0";

const MAX_TABLES: usize = 65_536;
const MAX_COLUMNS_PER_TABLE: usize = 1_000_000;
const MAX_IDENTITIES_PER_TABLE: usize = 10_000_000;
const MAX_LOOKUPS: usize = 1_000_000;
const MAX_LOOKUP_SIDES: usize = 10_000_000;
const MAX_LOOKUP_WIDTH: usize = 1_000_000;
const MAX_EXPRESSION_DEPTH: usize = 64;

/// Exact independent evaluation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AirEvaluationReport {
    /// Python JSON program commitment bound by the transport.
    pub source_program_commitment: [u8; 64],
    /// SHA3-512 commitment of the complete binary execution object.
    pub binary_commitment: [u8; 64],
    /// Number of identity-row evaluations.
    pub identities_evaluated: u64,
    /// Sum of enabled lookup weights across both multiset sides.
    pub lookup_messages_evaluated: u64,
    /// Maximum degree derived recursively from the encoded expressions.
    pub maximum_degree: u32,
}

/// Exact verifier-visible program parse result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AirProgramReport {
    pub source_program_commitment: [u8; 64],
    pub program_binary_commitment: [u8; 64],
    pub table_count: u32,
    pub trace_column_count: u64,
    pub identity_count: u64,
    pub lookup_count: u32,
    pub public_input_count: u32,
}

/// Fail-closed binary parsing or AIR evaluation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirIrError {
    EncodingLength,
    Truncated,
    TrailingBytes,
    Magic,
    Version,
    ZeroProgramCommitment,
    Text,
    CountLimit,
    DuplicateName,
    TableSchema,
    FixedColumn,
    Expression,
    ExpressionDepth,
    Identity,
    Lookup,
    PublicInput,
    TraceSchema,
    NonCanonicalField,
    FixedColumnMismatch,
    PublicInputMismatch,
    IdentityFailed,
    LookupSelectorNonBoolean,
    LookupWeightOutOfRange,
    LookupMultisetMismatch,
    ArithmeticOverflow,
}

impl fmt::Display for AirIrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Wave 1A binary AIR error: {self:?}")
    }
}

impl core::error::Error for AirIrError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Expr {
    Const(M31),
    Cell { column: usize, shift: usize },
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
}

impl Expr {
    #[cfg(feature = "std")]
    pub(crate) fn collect_columns(&self, columns: &mut alloc::collections::BTreeSet<usize>) {
        match self {
            Self::Const(_) => {}
            Self::Cell { column, .. } => {
                columns.insert(*column);
            }
            Self::Add(left, right) | Self::Sub(left, right) | Self::Mul(left, right) => {
                left.collect_columns(columns);
                right.collect_columns(columns);
            }
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn collect_columns_by_shift(
        &self,
        current: &mut alloc::collections::BTreeSet<usize>,
        next: &mut alloc::collections::BTreeSet<usize>,
    ) {
        match self {
            Self::Const(_) => {}
            Self::Cell { column, shift: 0 } => {
                current.insert(*column);
            }
            Self::Cell { column, shift: 1 } => {
                next.insert(*column);
            }
            Self::Cell { .. } => {}
            Self::Add(left, right) | Self::Sub(left, right) | Self::Mul(left, right) => {
                left.collect_columns_by_shift(current, next);
                right.collect_columns_by_shift(current, next);
            }
        }
    }

    pub(crate) fn degree(&self) -> Result<u32, AirIrError> {
        match self {
            Self::Const(_) => Ok(0),
            Self::Cell { .. } => Ok(1),
            Self::Add(left, right) | Self::Sub(left, right) => {
                Ok(left.degree()?.max(right.degree()?))
            }
            Self::Mul(left, right) => left
                .degree()?
                .checked_add(right.degree()?)
                .ok_or(AirIrError::ArithmeticOverflow),
        }
    }

    fn has_next(&self) -> bool {
        match self {
            Self::Const(_) => false,
            Self::Cell { shift, .. } => *shift == 1,
            Self::Add(left, right) | Self::Sub(left, right) | Self::Mul(left, right) => {
                left.has_next() || right.has_next()
            }
        }
    }

    fn validate_columns(&self, column_count: usize) -> Result<(), AirIrError> {
        match self {
            Self::Const(_) => Ok(()),
            Self::Cell { column, shift } => {
                if *column >= column_count || *shift > 1 {
                    return Err(AirIrError::Expression);
                }
                Ok(())
            }
            Self::Add(left, right) | Self::Sub(left, right) | Self::Mul(left, right) => {
                left.validate_columns(column_count)?;
                right.validate_columns(column_count)
            }
        }
    }

    pub(crate) fn evaluate(&self, columns: &[Vec<M31>], row: usize) -> Result<M31, AirIrError> {
        match self {
            Self::Const(value) => Ok(*value),
            Self::Cell { column, shift } => columns
                .get(*column)
                .and_then(|values| values.get(row.checked_add(*shift)?))
                .copied()
                .ok_or(AirIrError::Expression),
            Self::Add(left, right) => {
                Ok(left.evaluate(columns, row)? + right.evaluate(columns, row)?)
            }
            Self::Sub(left, right) => {
                Ok(left.evaluate(columns, row)? - right.evaluate(columns, row)?)
            }
            Self::Mul(left, right) => {
                Ok(left.evaluate(columns, row)? * right.evaluate(columns, row)?)
            }
        }
    }

    pub(crate) fn evaluate_extension(
        &self,
        current: &[Fp16],
        next: &[Fp16],
    ) -> Result<Fp16, AirIrError> {
        match self {
            Self::Const(value) => Ok(Fp16::from_m31(*value)),
            Self::Cell { column, shift: 0 } => {
                current.get(*column).copied().ok_or(AirIrError::Expression)
            }
            Self::Cell { column, shift: 1 } => {
                next.get(*column).copied().ok_or(AirIrError::Expression)
            }
            Self::Cell { .. } => Err(AirIrError::Expression),
            Self::Add(left, right) => Ok(left
                .evaluate_extension(current, next)?
                .add(right.evaluate_extension(current, next)?)),
            Self::Sub(left, right) => Ok(left
                .evaluate_extension(current, next)?
                .sub(right.evaluate_extension(current, next)?)),
            Self::Mul(left, right) => Ok(left
                .evaluate_extension(current, next)?
                .mul(right.evaluate_extension(current, next)?)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityFamily {
    Local,
    Transition,
    Boundary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) _name: String,
    pub(crate) family: IdentityFamily,
    pub(crate) row_start: usize,
    pub(crate) row_stop: usize,
    pub(crate) expression: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FixedColumn {
    Explicit(Vec<M31>),
    Runs {
        runs: Vec<(M31, usize)>,
        rows: usize,
    },
    Periodic {
        pattern: Vec<M31>,
        rows: usize,
    },
}

impl FixedColumn {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Explicit(values) => values.len(),
            Self::Runs { rows, .. } | Self::Periodic { rows, .. } => *rows,
        }
    }

    pub(crate) fn get(&self, index: usize) -> Option<M31> {
        match self {
            Self::Explicit(values) => values.get(index).copied(),
            Self::Runs { runs, rows } => {
                if index >= *rows {
                    return None;
                }
                let mut offset = index;
                for (value, count) in runs {
                    if offset < *count {
                        return Some(*value);
                    }
                    offset -= *count;
                }
                None
            }
            Self::Periodic { pattern, rows } => (index < *rows)
                .then(|| pattern.get(index % pattern.len()).copied())
                .flatten(),
        }
    }

    pub(crate) fn materialize(&self) -> Vec<M31> {
        match self {
            Self::Explicit(values) => values.clone(),
            _ => (0..self.len())
                .map(|index| self.get(index).expect("validated fixed-column index"))
                .collect(),
        }
    }

    fn matches(&self, values: &[M31]) -> bool {
        self.len() == values.len()
            && values
                .iter()
                .enumerate()
                .all(|(index, value)| self.get(index) == Some(*value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Table {
    pub(crate) _name: String,
    pub(crate) rows: usize,
    pub(crate) columns: Vec<String>,
    pub(crate) fixed_columns: Vec<(usize, FixedColumn)>,
    pub(crate) identities: Vec<Identity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LookupSide {
    pub(crate) table: usize,
    pub(crate) row_start: usize,
    pub(crate) row_stop: usize,
    pub(crate) selector: Expr,
    pub(crate) weight: Expr,
    pub(crate) values: Vec<Expr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Lookup {
    pub(crate) _name: String,
    pub(crate) sources: Vec<LookupSide>,
    pub(crate) destinations: Vec<LookupSide>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicInputBinding {
    pub(crate) _name: String,
    pub(crate) table: usize,
    pub(crate) column: usize,
    pub(crate) row: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedExecution {
    pub(crate) source_program_commitment: [u8; 64],
    pub(crate) _program_id: String,
    pub(crate) tables: Vec<Table>,
    pub(crate) lookups: Vec<Lookup>,
    pub(crate) public_inputs: Vec<PublicInputBinding>,
    pub(crate) traces: Vec<Vec<Vec<M31>>>,
    pub(crate) supplied_public_inputs: Vec<M31>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedProgram {
    pub(crate) source_program_commitment: [u8; 64],
    pub(crate) program_id: String,
    pub(crate) tables: Vec<Table>,
    pub(crate) lookups: Vec<Lookup>,
    pub(crate) public_inputs: Vec<PublicInputBinding>,
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, AirIrError> {
        if encoded.is_empty() || encoded.len() > MAX_AIR_BINARY_BYTES {
            return Err(AirIrError::EncodingLength);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn remaining(&self) -> usize {
        self.encoded.len() - self.offset
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], AirIrError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AirIrError::ArithmeticOverflow)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(AirIrError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, AirIrError> {
        Ok(self.raw(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AirIrError> {
        Ok(u16::from_be_bytes(
            self.raw(2)?.try_into().map_err(|_| AirIrError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, AirIrError> {
        Ok(u32::from_be_bytes(
            self.raw(4)?.try_into().map_err(|_| AirIrError::Truncated)?,
        ))
    }

    fn count(&mut self, limit: usize) -> Result<usize, AirIrError> {
        let value = usize::try_from(self.u32()?).map_err(|_| AirIrError::CountLimit)?;
        if value > limit || value > self.remaining().saturating_add(1) {
            return Err(AirIrError::CountLimit);
        }
        Ok(value)
    }

    fn text(&mut self) -> Result<String, AirIrError> {
        let length = usize::from(self.u16()?);
        if length == 0 {
            return Err(AirIrError::Text);
        }
        let bytes = self.raw(length)?;
        if !bytes.is_ascii() {
            return Err(AirIrError::Text);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| AirIrError::Text)
    }

    fn field(&mut self) -> Result<M31, AirIrError> {
        M31::from_canonical(self.u32()?).map_err(|_| AirIrError::NonCanonicalField)
    }

    fn expression(&mut self, depth: usize) -> Result<Expr, AirIrError> {
        if depth > MAX_EXPRESSION_DEPTH {
            return Err(AirIrError::ExpressionDepth);
        }
        match self.u8()? {
            0 => Ok(Expr::Const(self.field()?)),
            1 => {
                let column = usize::try_from(self.u32()?).map_err(|_| AirIrError::Expression)?;
                let shift = usize::from(self.u8()?);
                if shift > 1 {
                    return Err(AirIrError::Expression);
                }
                Ok(Expr::Cell { column, shift })
            }
            2 => Ok(Expr::Add(
                Box::new(self.expression(depth + 1)?),
                Box::new(self.expression(depth + 1)?),
            )),
            3 => Ok(Expr::Sub(
                Box::new(self.expression(depth + 1)?),
                Box::new(self.expression(depth + 1)?),
            )),
            4 => Ok(Expr::Mul(
                Box::new(self.expression(depth + 1)?),
                Box::new(self.expression(depth + 1)?),
            )),
            _ => Err(AirIrError::Expression),
        }
    }
}

fn parse_side(reader: &mut Reader<'_>, tables: &[Table]) -> Result<LookupSide, AirIrError> {
    let table = usize::try_from(reader.u32()?).map_err(|_| AirIrError::Lookup)?;
    let table_metadata = tables.get(table).ok_or(AirIrError::Lookup)?;
    let row_start = usize::try_from(reader.u32()?).map_err(|_| AirIrError::Lookup)?;
    let row_stop = usize::try_from(reader.u32()?).map_err(|_| AirIrError::Lookup)?;
    if row_start >= row_stop || row_stop > table_metadata.rows {
        return Err(AirIrError::Lookup);
    }
    let selector = reader.expression(0)?;
    let weight = reader.expression(0)?;
    let value_count = reader.count(MAX_LOOKUP_WIDTH)?;
    if value_count == 0 {
        return Err(AirIrError::Lookup);
    }
    let mut values = Vec::with_capacity(value_count);
    for _ in 0..value_count {
        values.push(reader.expression(0)?);
    }
    for expression in values.iter().chain([&selector, &weight]) {
        expression.validate_columns(table_metadata.columns.len())?;
    }
    if selector.degree()? > 1 || selector.has_next() || weight.degree()? > 1 || weight.has_next() {
        return Err(AirIrError::Lookup);
    }
    Ok(LookupSide {
        table,
        row_start,
        row_stop,
        selector,
        weight,
        values,
    })
}

fn parse_program_body(reader: &mut Reader<'_>, version: u16) -> Result<ParsedProgram, AirIrError> {
    let source_program_commitment: [u8; 64] = reader
        .raw(64)?
        .try_into()
        .map_err(|_| AirIrError::Truncated)?;
    if !source_program_commitment.iter().any(|value| *value != 0) {
        return Err(AirIrError::ZeroProgramCommitment);
    }
    let program_id = reader.text()?;
    let table_count = reader.count(MAX_TABLES)?;
    if table_count == 0 {
        return Err(AirIrError::TableSchema);
    }
    let mut table_names = BTreeSet::new();
    let mut tables = Vec::with_capacity(table_count);
    for _ in 0..table_count {
        let name = reader.text()?;
        if !table_names.insert(name.clone()) {
            return Err(AirIrError::DuplicateName);
        }
        let rows = usize::try_from(reader.u32()?).map_err(|_| AirIrError::TableSchema)?;
        if rows == 0 {
            return Err(AirIrError::TableSchema);
        }
        let column_count = reader.count(MAX_COLUMNS_PER_TABLE)?;
        if column_count == 0 {
            return Err(AirIrError::TableSchema);
        }
        let mut column_names = BTreeSet::new();
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let column = reader.text()?;
            if !column_names.insert(column.clone()) {
                return Err(AirIrError::DuplicateName);
            }
            columns.push(column);
        }
        let fixed_count = reader.count(column_count)?;
        let mut fixed_indices = BTreeSet::new();
        let mut fixed_columns = Vec::with_capacity(fixed_count);
        for _ in 0..fixed_count {
            let column = usize::try_from(reader.u32()?).map_err(|_| AirIrError::FixedColumn)?;
            if column >= column_count || !fixed_indices.insert(column) {
                return Err(AirIrError::FixedColumn);
            }
            let values = if version == AIR_BINARY_VERSION {
                let value_count = reader.count(rows)?;
                if value_count != rows {
                    return Err(AirIrError::FixedColumn);
                }
                let mut values = Vec::with_capacity(rows);
                for _ in 0..rows {
                    values.push(reader.field()?);
                }
                FixedColumn::Explicit(values)
            } else {
                match reader.u8()? {
                    0 => {
                        let value_count = reader.count(rows)?;
                        if value_count != rows {
                            return Err(AirIrError::FixedColumn);
                        }
                        let mut values = Vec::with_capacity(rows);
                        for _ in 0..rows {
                            values.push(reader.field()?);
                        }
                        FixedColumn::Explicit(values)
                    }
                    1 => {
                        let run_count = reader.count(rows)?;
                        if run_count == 0 {
                            return Err(AirIrError::FixedColumn);
                        }
                        let mut runs = Vec::with_capacity(run_count);
                        let mut total = 0_usize;
                        let mut previous = None;
                        for _ in 0..run_count {
                            let value = reader.field()?;
                            let count = usize::try_from(reader.u32()?)
                                .map_err(|_| AirIrError::FixedColumn)?;
                            if count == 0 || previous == Some(value) {
                                return Err(AirIrError::FixedColumn);
                            }
                            total = total
                                .checked_add(count)
                                .ok_or(AirIrError::ArithmeticOverflow)?;
                            if total > rows {
                                return Err(AirIrError::FixedColumn);
                            }
                            runs.push((value, count));
                            previous = Some(value);
                        }
                        if total != rows {
                            return Err(AirIrError::FixedColumn);
                        }
                        FixedColumn::Runs { runs, rows }
                    }
                    2 => {
                        let pattern_count = reader.count(rows)?;
                        if pattern_count == 0 || rows % pattern_count != 0 {
                            return Err(AirIrError::FixedColumn);
                        }
                        let mut pattern = Vec::with_capacity(pattern_count);
                        for _ in 0..pattern_count {
                            pattern.push(reader.field()?);
                        }
                        FixedColumn::Periodic { pattern, rows }
                    }
                    _ => return Err(AirIrError::FixedColumn),
                }
            };
            fixed_columns.push((column, values));
        }
        let identity_count = reader.count(MAX_IDENTITIES_PER_TABLE)?;
        let mut identity_names = BTreeSet::new();
        let mut identities = Vec::with_capacity(identity_count);
        for _ in 0..identity_count {
            let identity_name = reader.text()?;
            if !identity_names.insert(identity_name.clone()) {
                return Err(AirIrError::DuplicateName);
            }
            let family = match reader.u8()? {
                0 => IdentityFamily::Local,
                1 => IdentityFamily::Transition,
                2 => IdentityFamily::Boundary,
                _ => return Err(AirIrError::Identity),
            };
            let row_start = usize::try_from(reader.u32()?).map_err(|_| AirIrError::Identity)?;
            let row_stop = usize::try_from(reader.u32()?).map_err(|_| AirIrError::Identity)?;
            if row_start >= row_stop
                || row_stop > rows
                || (family == IdentityFamily::Transition && row_stop >= rows)
            {
                return Err(AirIrError::Identity);
            }
            let expression = reader.expression(0)?;
            expression.validate_columns(column_count)?;
            if family != IdentityFamily::Transition && expression.has_next() {
                return Err(AirIrError::Identity);
            }
            identities.push(Identity {
                _name: identity_name,
                family,
                row_start,
                row_stop,
                expression,
            });
        }
        tables.push(Table {
            _name: name,
            rows,
            columns,
            fixed_columns,
            identities,
        });
    }

    let lookup_count = reader.count(MAX_LOOKUPS)?;
    let mut lookup_names = BTreeSet::new();
    let mut lookups = Vec::with_capacity(lookup_count);
    for _ in 0..lookup_count {
        let name = reader.text()?;
        if !lookup_names.insert(name.clone()) {
            return Err(AirIrError::DuplicateName);
        }
        let source_count = reader.count(MAX_LOOKUP_SIDES)?;
        if source_count == 0 {
            return Err(AirIrError::Lookup);
        }
        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            sources.push(parse_side(reader, &tables)?);
        }
        let destination_count = reader.count(MAX_LOOKUP_SIDES)?;
        if destination_count == 0 {
            return Err(AirIrError::Lookup);
        }
        let mut destinations = Vec::with_capacity(destination_count);
        for _ in 0..destination_count {
            destinations.push(parse_side(reader, &tables)?);
        }
        let width = sources[0].values.len();
        if sources
            .iter()
            .chain(&destinations)
            .any(|side| side.values.len() != width)
        {
            return Err(AirIrError::Lookup);
        }
        lookups.push(Lookup {
            _name: name,
            sources,
            destinations,
        });
    }

    let public_count = reader.count(MAX_LOOKUP_SIDES)?;
    let mut public_names = BTreeSet::new();
    let mut public_inputs = Vec::with_capacity(public_count);
    for _ in 0..public_count {
        let name = reader.text()?;
        if !public_names.insert(name.clone()) {
            return Err(AirIrError::DuplicateName);
        }
        let table = usize::try_from(reader.u32()?).map_err(|_| AirIrError::PublicInput)?;
        let column = usize::try_from(reader.u32()?).map_err(|_| AirIrError::PublicInput)?;
        let row = usize::try_from(reader.u32()?).map_err(|_| AirIrError::PublicInput)?;
        let metadata = tables.get(table).ok_or(AirIrError::PublicInput)?;
        if column >= metadata.columns.len() || row >= metadata.rows {
            return Err(AirIrError::PublicInput);
        }
        public_inputs.push(PublicInputBinding {
            _name: name,
            table,
            column,
            row,
        });
    }

    Ok(ParsedProgram {
        source_program_commitment,
        program_id,
        tables,
        lookups,
        public_inputs,
    })
}

pub(crate) fn parse_execution(encoded: &[u8]) -> Result<ParsedExecution, AirIrError> {
    let mut reader = Reader::new(encoded)?;
    if reader.raw(AIR_BINARY_MAGIC.len())? != AIR_BINARY_MAGIC {
        return Err(AirIrError::Magic);
    }
    let version = reader.u16()?;
    if !matches!(
        version,
        AIR_BINARY_VERSION | AIR_BINARY_COMPACT_FIXED_VERSION
    ) {
        return Err(AirIrError::Version);
    }
    let ParsedProgram {
        source_program_commitment,
        program_id,
        tables,
        lookups,
        public_inputs,
    } = parse_program_body(&mut reader, version)?;
    if reader.count(MAX_TABLES)? != tables.len() {
        return Err(AirIrError::TraceSchema);
    }
    let mut traces = Vec::with_capacity(tables.len());
    for (expected_index, table) in tables.iter().enumerate() {
        let table_index = usize::try_from(reader.u32()?).map_err(|_| AirIrError::TraceSchema)?;
        let column_count = reader.count(MAX_COLUMNS_PER_TABLE)?;
        let rows = usize::try_from(reader.u32()?).map_err(|_| AirIrError::TraceSchema)?;
        if table_index != expected_index
            || column_count != table.columns.len()
            || rows != table.rows
        {
            return Err(AirIrError::TraceSchema);
        }
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let mut values = Vec::with_capacity(rows);
            for _ in 0..rows {
                values.push(reader.field()?);
            }
            columns.push(values);
        }
        traces.push(columns);
    }
    let supplied_count = reader.count(MAX_LOOKUP_SIDES)?;
    if supplied_count != public_inputs.len() {
        return Err(AirIrError::PublicInput);
    }
    let mut supplied_public_inputs = Vec::with_capacity(supplied_count);
    for _ in 0..supplied_count {
        supplied_public_inputs.push(reader.field()?);
    }
    if reader.remaining() != 0 {
        return Err(AirIrError::TrailingBytes);
    }
    Ok(ParsedExecution {
        source_program_commitment,
        _program_id: program_id,
        tables,
        lookups,
        public_inputs,
        traces,
        supplied_public_inputs,
    })
}

fn side_capacity(sides: &[LookupSide]) -> Result<u64, AirIrError> {
    sides.iter().try_fold(0_u64, |total, side| {
        total
            .checked_add((side.row_stop - side.row_start) as u64)
            .ok_or(AirIrError::ArithmeticOverflow)
    })
}

/// Parse verifier-visible AIR metadata without accepting or exposing a witness.
pub(crate) fn parse_air_program(encoded: &[u8]) -> Result<ParsedProgram, AirIrError> {
    let mut reader = Reader::new(encoded)?;
    if reader.raw(AIR_PROGRAM_MAGIC.len())? != AIR_PROGRAM_MAGIC {
        return Err(AirIrError::Magic);
    }
    let version = reader.u16()?;
    if !matches!(
        version,
        AIR_BINARY_VERSION | AIR_BINARY_COMPACT_FIXED_VERSION
    ) {
        return Err(AirIrError::Version);
    }
    let parsed = parse_program_body(&mut reader, version)?;
    if reader.remaining() != 0 {
        return Err(AirIrError::TrailingBytes);
    }
    Ok(parsed)
}

/// Parse verifier-visible AIR metadata without accepting or exposing a witness.
pub fn validate_air_program(encoded: &[u8]) -> Result<AirProgramReport, AirIrError> {
    let parsed = parse_air_program(encoded)?;
    let table_count = u32::try_from(parsed.tables.len()).map_err(|_| AirIrError::CountLimit)?;
    let trace_column_count = parsed.tables.iter().try_fold(0_u64, |total, table| {
        total
            .checked_add(table.columns.len() as u64)
            .ok_or(AirIrError::ArithmeticOverflow)
    })?;
    let identity_count = parsed.tables.iter().try_fold(0_u64, |total, table| {
        total
            .checked_add(table.identities.len() as u64)
            .ok_or(AirIrError::ArithmeticOverflow)
    })?;
    let lookup_count = u32::try_from(parsed.lookups.len()).map_err(|_| AirIrError::CountLimit)?;
    let public_input_count =
        u32::try_from(parsed.public_inputs.len()).map_err(|_| AirIrError::CountLimit)?;
    let mut hasher = Sha3_512::new();
    hasher.update(AIR_PROGRAM_DOMAIN);
    hasher.update(encoded);
    Ok(AirProgramReport {
        source_program_commitment: parsed.source_program_commitment,
        program_binary_commitment: hasher.finalize().into(),
        table_count,
        trace_column_count,
        identity_count,
        lookup_count,
        public_input_count,
    })
}

fn evaluate_sides(
    sides: &[LookupSide],
    traces: &[Vec<Vec<M31>>],
    opposing_capacity: u64,
) -> Result<(BTreeMap<Vec<u32>, u64>, u64), AirIrError> {
    let mut counter = BTreeMap::<Vec<u32>, u64>::new();
    let mut evaluated = 0_u64;
    for side in sides {
        let columns = traces.get(side.table).ok_or(AirIrError::TraceSchema)?;
        for row in side.row_start..side.row_stop {
            let selector = side.selector.evaluate(columns, row)?.as_u32();
            if selector > 1 {
                return Err(AirIrError::LookupSelectorNonBoolean);
            }
            if selector == 0 {
                continue;
            }
            let weight = u64::from(side.weight.evaluate(columns, row)?.as_u32());
            if weight > opposing_capacity {
                return Err(AirIrError::LookupWeightOutOfRange);
            }
            if weight == 0 {
                continue;
            }
            let key = side
                .values
                .iter()
                .map(|value| value.evaluate(columns, row).map(M31::as_u32))
                .collect::<Result<Vec<_>, _>>()?;
            let entry = counter.entry(key).or_insert(0);
            *entry = entry
                .checked_add(weight)
                .ok_or(AirIrError::ArithmeticOverflow)?;
            evaluated = evaluated
                .checked_add(weight)
                .ok_or(AirIrError::ArithmeticOverflow)?;
        }
    }
    Ok((counter, evaluated))
}

/// Parse and independently evaluate one complete binary AIR execution object.
pub fn evaluate_air_execution(encoded: &[u8]) -> Result<AirEvaluationReport, AirIrError> {
    let parsed = parse_execution(encoded)?;
    let mut maximum_degree = 0_u32;
    let mut identities_evaluated = 0_u64;
    for (table, trace) in parsed.tables.iter().zip(&parsed.traces) {
        for (column, expected) in &table.fixed_columns {
            if trace
                .get(*column)
                .is_none_or(|values| !expected.matches(values))
            {
                return Err(AirIrError::FixedColumnMismatch);
            }
        }
        for identity in &table.identities {
            maximum_degree = maximum_degree.max(identity.expression.degree()?);
            for row in identity.row_start..identity.row_stop {
                identities_evaluated = identities_evaluated
                    .checked_add(1)
                    .ok_or(AirIrError::ArithmeticOverflow)?;
                if !identity.expression.evaluate(trace, row)?.is_zero() {
                    return Err(AirIrError::IdentityFailed);
                }
            }
        }
    }
    for (binding, supplied) in parsed
        .public_inputs
        .iter()
        .zip(&parsed.supplied_public_inputs)
    {
        let observed = parsed
            .traces
            .get(binding.table)
            .and_then(|columns| columns.get(binding.column))
            .and_then(|values| values.get(binding.row))
            .ok_or(AirIrError::PublicInput)?;
        if observed != supplied {
            return Err(AirIrError::PublicInputMismatch);
        }
    }

    let mut lookup_messages_evaluated = 0_u64;
    for lookup in &parsed.lookups {
        let source_capacity = side_capacity(&lookup.sources)?;
        let destination_capacity = side_capacity(&lookup.destinations)?;
        let (source, source_count) =
            evaluate_sides(&lookup.sources, &parsed.traces, destination_capacity)?;
        let (destination, destination_count) =
            evaluate_sides(&lookup.destinations, &parsed.traces, source_capacity)?;
        if source != destination {
            return Err(AirIrError::LookupMultisetMismatch);
        }
        lookup_messages_evaluated = lookup_messages_evaluated
            .checked_add(source_count)
            .and_then(|value| value.checked_add(destination_count))
            .ok_or(AirIrError::ArithmeticOverflow)?;
    }

    let mut hasher = Sha3_512::new();
    hasher.update(AIR_BINARY_DOMAIN);
    hasher.update(encoded);
    Ok(AirEvaluationReport {
        source_program_commitment: parsed.source_program_commitment,
        binary_commitment: hasher.finalize().into(),
        identities_evaluated,
        lookup_messages_evaluated,
        maximum_degree,
    })
}

/// Return the public inputs carried by a fully validated execution object.
///
/// This deliberately exposes no witness columns.  Deployment-shaped proof
/// entrypoints need the verifier-visible values without duplicating the
/// canonical binary parser or weakening any of its structural checks.
pub fn validated_execution_public_inputs(encoded: &[u8]) -> Result<Vec<M31>, AirIrError> {
    let parsed = parse_execution(encoded)?;
    for (binding, supplied) in parsed
        .public_inputs
        .iter()
        .zip(&parsed.supplied_public_inputs)
    {
        let observed = parsed
            .traces
            .get(binding.table)
            .and_then(|columns| columns.get(binding.column))
            .and_then(|values| values.get(binding.row))
            .ok_or(AirIrError::PublicInput)?;
        if observed != supplied {
            return Err(AirIrError::PublicInputMismatch);
        }
    }
    Ok(parsed.supplied_public_inputs)
}

/// Return the complete witness columns after the binary execution has passed
/// its public-input consistency checks.  Callers must run
/// [`evaluate_air_execution`] first when they need the identities, fixed
/// columns, and lookup multisets checked as well; this accessor intentionally
/// performs no second, partial evaluation that could be mistaken for the
/// full verifier.
pub fn validated_execution_traces(encoded: &[u8]) -> Result<Vec<Vec<Vec<M31>>>, AirIrError> {
    let parsed = parse_execution(encoded)?;
    for (binding, supplied) in parsed
        .public_inputs
        .iter()
        .zip(&parsed.supplied_public_inputs)
    {
        let observed = parsed
            .traces
            .get(binding.table)
            .and_then(|columns| columns.get(binding.column))
            .and_then(|values| values.get(binding.row))
            .ok_or(AirIrError::PublicInput)?;
        if observed != supplied {
            return Err(AirIrError::PublicInputMismatch);
        }
    }
    Ok(parsed.traces)
}
