import Admission.Model

@[export bla_raw]
def blaRaw (x : UInt64) : UInt64 := x + 1

@[export bla_byte]
def blaByte (x : UInt8) : UInt8 := x + 1

@[export bla_bool]
def blaBool (x : Bool) : Bool := !x

@[export bla_bytes]
def blaBytes (x : ByteArray) : ByteArray := x

@[export bla_len]
def blaLen (x : ByteArray) : UInt64 := x.size.toUInt64
