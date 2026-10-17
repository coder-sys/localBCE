import Lake
open Lake DSL

package providerApp where
  version := v!"0.1.0"
  buildDir := ".lake/provider-lean-split-r7"
  moreLeanArgs := #["-j1"]

lean_lib providerAppSemantics where
  roots := #[`Semantics, `InputProtocol]

lean_exe providerAppLean where
  root := `Main
  needs := #[providerAppSemantics]
