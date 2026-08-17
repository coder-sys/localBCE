#include "native_v3_source_assertion_canonical.h"

#include <algorithm>
#include <array>

namespace blind_ledger_longfellow::source_assertion_verifier {
namespace {

using blind_ledger_longfellow::source_assertion::Digest;
using blind_ledger_longfellow::source_assertion::ProofRole;
using blind_ledger_longfellow::source_assertion::RelationField;
using blind_ledger_longfellow::source_assertion::Statement;

class Cursor {
 public:
  explicit Cursor(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}

  bool Byte(uint8_t& value) {
    if (offset_ >= bytes_.size()) return false;
    value = bytes_[offset_++];
    return true;
  }

  bool Digest(Digest& value) {
    if (bytes_.size() - offset_ < value.size()) return false;
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                value.size(), value.begin());
    offset_ += value.size();
    return true;
  }

  bool Role(ProofRole& value) {
    if (bytes_.size() - offset_ < value.size()) return false;
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                value.size(), value.begin());
    offset_ += value.size();
    return true;
  }

  bool U64(uint64_t& value) {
    if (bytes_.size() - offset_ < sizeof(value)) return false;
    value = 0;
    for (size_t index = 0; index < sizeof(value); ++index) {
      value = (value << 8) | bytes_[offset_++];
    }
    return true;
  }

  size_t offset() const { return offset_; }

 private:
  const std::vector<uint8_t>& bytes_;
  size_t offset_ = 0;
};

bool IsZero(const Digest& value) {
  return std::all_of(value.begin(), value.end(), [](uint8_t byte) {
    return byte == 0;
  });
}

bool IsBinary(uint8_t value) { return value == 0 || value == 1; }

void PushDigest(proofs::DenseFiller<RelationField>& filler,
                const Digest& value, const RelationField& field) {
  for (uint8_t byte : value) filler.push_back(byte, 8, field);
}

void PushPublic(proofs::DenseFiller<RelationField>& filler,
                const Statement& statement, const RelationField& field) {
  // The first field is Longfellow's required one-wire.  All following
  // byte-sized values use LSB-first bit order, while typed uint64 values are
  // packed as native numeric wires.  The decoder above is the only place
  // that converts the canonical big-endian wire bytes into those values.
  filler.push_back(field.one());
  filler.push_back(statement.protocol_version, 8, field);
  PushDigest(filler, statement.proof_suite, field);
  for (uint8_t byte : statement.proof_role) filler.push_back(byte, 8, field);
  PushDigest(filler, statement.execution_context, field);
  PushDigest(filler, statement.source_registry_snapshot, field);
  PushDigest(filler, statement.source_profile, field);
  PushDigest(filler, statement.governance_snapshot, field);
  PushDigest(filler, statement.automatic_control_set, field);
  PushDigest(filler, statement.settlement_domain, field);
  PushDigest(filler, statement.subject_scope, field);
  filler.push_back(statement.epoch, 64, field);
  filler.push_back(statement.sequence_before, 64, field);
  PushDigest(filler, statement.state_before_id, field);
  PushDigest(filler, statement.request_id, field);
  PushDigest(filler, statement.source_root_id, field);
  PushDigest(filler, statement.completeness_id, field);
  PushDigest(filler, statement.decision_path_id, field);
  PushDigest(filler, statement.exception_id, field);
  filler.push_back(statement.active, 8, field);
  filler.push_back(statement.complete, 8, field);
  filler.push_back(statement.authoritative_membership, 8, field);
  filler.push_back(statement.authoritative_absence, 8, field);
  PushDigest(filler, statement.private_batch_commitment, field);
}

}  // namespace

bool CanonicalStatementDecoder::Decode(const std::vector<uint8_t>& bytes,
                                       Statement& statement,
                                       std::string& reason) {
  if (bytes.size() != kStatementBytes) {
    reason = "statement.length";
    return false;
  }
  Cursor cursor(bytes);
  if (!cursor.Byte(statement.protocol_version) ||
      !cursor.Digest(statement.proof_suite) ||
      !cursor.Role(statement.proof_role) ||
      !cursor.Digest(statement.execution_context) ||
      !cursor.Digest(statement.source_registry_snapshot) ||
      !cursor.Digest(statement.source_profile) ||
      !cursor.Digest(statement.governance_snapshot) ||
      !cursor.Digest(statement.automatic_control_set) ||
      !cursor.Digest(statement.settlement_domain) ||
      !cursor.Digest(statement.subject_scope) ||
      !cursor.U64(statement.epoch) ||
      !cursor.U64(statement.sequence_before) ||
      !cursor.Digest(statement.state_before_id) ||
      !cursor.Digest(statement.request_id) ||
      !cursor.Digest(statement.source_root_id) ||
      !cursor.Digest(statement.completeness_id) ||
      !cursor.Digest(statement.decision_path_id) ||
      !cursor.Digest(statement.exception_id) ||
      !cursor.Byte(statement.active) || !cursor.Byte(statement.complete) ||
      !cursor.Byte(statement.authoritative_membership) ||
      !cursor.Byte(statement.authoritative_absence) ||
      !cursor.Digest(statement.private_batch_commitment) ||
      cursor.offset() != bytes.size()) {
    reason = "statement.truncated-or-trailing";
    return false;
  }
  if (statement.protocol_version != 3) {
    reason = "statement.protocol";
    return false;
  }
  for (size_t index = 0; index < statement.proof_role.size(); ++index) {
    if (statement.proof_role[index] !=
        static_cast<uint8_t>(source_assertion::kProofRole[index])) {
      reason = "statement.proof-role";
      return false;
    }
  }
  if (!IsZero(statement.proof_suite)) {
    reason = "statement.proof-suite";
    return false;
  }
  if (!IsBinary(statement.active) || !IsBinary(statement.complete) ||
      !IsBinary(statement.authoritative_membership) ||
      !IsBinary(statement.authoritative_absence)) {
    reason = "statement.flag-not-binary";
    return false;
  }
  return true;
}

bool CanonicalStatementDecoder::PackPublicInput(
    const Statement& statement, const RelationField& field,
    proofs::Dense<RelationField>& public_input, std::string& reason) {
  if (public_input.n0_ != 1 || public_input.n1_ != kPublicFieldCount) {
    reason = "public-input.length";
    return false;
  }
  proofs::DenseFiller<RelationField> filler(public_input);
  PushPublic(filler, statement, field);
  if (filler.size() != kPublicFieldCount) {
    reason = "public-input.count";
    return false;
  }
  return true;
}

}  // namespace blind_ledger_longfellow::source_assertion_verifier
