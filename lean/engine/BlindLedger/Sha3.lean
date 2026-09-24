import Std

namespace BlindLedger.Semantic

abbrev Bytes := ByteArray

private def rotl64 (value : UInt64) (amount : Nat) : UInt64 :=
  if amount = 0 then value
  else (value <<< UInt64.ofNat amount) ||| (value >>> UInt64.ofNat (64 - amount))

private def laneIndex (x y : Nat) : Nat := x + 5 * y

private def lane (state : Array UInt64) (index : Nat) : UInt64 := state[index]!

private def loadLane (data : Bytes) (offset : Nat) : UInt64 := Id.run do
  let mut value : UInt64 := 0
  for index in [0:8] do
    value := value ||| ((data.get! (offset + index)).toUInt64 <<< UInt64.ofNat (8 * index))
  value

private def storeLane (value : UInt64) : Bytes :=
  let word := value.toNat
  ByteArray.mk #[
    UInt8.ofNat (word % 256),
    UInt8.ofNat ((word / 256) % 256),
    UInt8.ofNat ((word / 65_536) % 256),
    UInt8.ofNat ((word / 16_777_216) % 256),
    UInt8.ofNat ((word / 4_294_967_296) % 256),
    UInt8.ofNat ((word / 1_099_511_627_776) % 256),
    UInt8.ofNat ((word / 281_474_976_710_656) % 256),
    UInt8.ofNat ((word / 72_057_594_037_927_936) % 256)]

private def roundConstants : Array UInt64 := #[
  0x0000000000000001, 0x0000000000008082,
  0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088,
  0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B,
  0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080,
  0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080,
  0x0000000080000001, 0x8000000080008008]

private def rhoOffsets : Array Nat := #[
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14]

private def keccakRound (state : Array UInt64) (round : Nat) : Array UInt64 := Id.run do
  let mut c := Array.replicate 5 (0 : UInt64)
  for x in [0:5] do
    let mut value : UInt64 := 0
    for y in [0:5] do
      value := value ^^^ lane state (laneIndex x y)
    c := Array.set! c x value
  let mut d := Array.replicate 5 (0 : UInt64)
  for x in [0:5] do
    d := Array.set! d x (lane c ((x + 4) % 5) ^^^ rotl64 (lane c ((x + 1) % 5)) 1)
  let mut afterTheta := state
  for x in [0:5] do
    for y in [0:5] do
      let index := laneIndex x y
      afterTheta := Array.set! afterTheta index (lane afterTheta index ^^^ lane d x)
  let mut b := Array.replicate 25 (0 : UInt64)
  for x in [0:5] do
    for y in [0:5] do
      let source := laneIndex x y
      let target := laneIndex y ((2 * x + 3 * y) % 5)
      b := Array.set! b target (rotl64 (lane afterTheta source) (rhoOffsets[source]!))
  let mut afterChi := b
  for y in [0:5] do
    for x in [0:5] do
      let current := laneIndex x y
      let next := laneIndex ((x + 1) % 5) y
      let nextNext := laneIndex ((x + 2) % 5) y
      afterChi := Array.set! afterChi current
        (lane b current ^^^ ((~~~(lane b next)) &&& lane b nextNext))
  Array.set! afterChi 0 (lane afterChi 0 ^^^ roundConstants[round]!)

private def keccakF (state : Array UInt64) : Array UInt64 := Id.run do
  let mut current := state
  for round in [0:24] do
    current := keccakRound current round
  current

private def pad (data : Bytes) : Bytes := Id.run do
  let rate := 72
  let blocks := data.size / rate + 1
  let total := blocks * rate
  let mut result := ByteArray.append data (List.replicate (total - data.size) (UInt8.ofNat 0) |>.toByteArray)
  result := result.set! data.size (UInt8.ofNat 0x06)
  result := result.set! (total - 1) (result.get! (total - 1) ||| UInt8.ofNat 0x80)
  result

def sha3_512 (data : Bytes) : Bytes := Id.run do
  let rate := 72
  let padded := pad data
  let mut state := Array.replicate 25 (0 : UInt64)
  for block in [0:padded.size / rate] do
    for index in [0:9] do
      let laneIndex := index
      let offset := block * rate + index * 8
      state := Array.set! state laneIndex (lane state laneIndex ^^^ loadLane padded offset)
    state := keccakF state
  let mut result := ByteArray.empty
  for index in [0:8] do
    result := ByteArray.append result (storeLane (lane state index))
  result

end BlindLedger.Semantic
