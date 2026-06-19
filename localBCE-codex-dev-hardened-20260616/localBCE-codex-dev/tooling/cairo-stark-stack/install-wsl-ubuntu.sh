#!/usr/bin/env bash
set -euo pipefail

SCARB_VERSION="${SCARB_VERSION:-2.18.0}"
SCARB_ARCHIVE="scarb-v${SCARB_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
SCARB_BASE="https://github.com/software-mansion/scarb/releases/download/v${SCARB_VERSION}"
INSTALL_ROOT="${HOME}/.scarb/${SCARB_VERSION}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

echo "== Base packages =="
if need_cmd apt-get; then
  sudo apt-get update
  sudo apt-get install -y curl ca-certificates tar gzip build-essential pkg-config libssl-dev git
fi

echo "== Rust / Cargo =="
if ! need_cmd cargo; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
  sh /tmp/rustup-init.sh -y
  # shellcheck source=/dev/null
  . "${HOME}/.cargo/env"
fi

echo "== Scarb ${SCARB_VERSION} =="
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
curl -L --retry 5 --retry-delay 2 -o "${tmpdir}/${SCARB_ARCHIVE}" "${SCARB_BASE}/${SCARB_ARCHIVE}"
curl -L --retry 5 --retry-delay 2 -o "${tmpdir}/checksums.sha256" "${SCARB_BASE}/checksums.sha256"
expected="$(grep " ${SCARB_ARCHIVE}$" "${tmpdir}/checksums.sha256" | awk '{print $1}')"
actual="$(sha256sum "${tmpdir}/${SCARB_ARCHIVE}" | awk '{print $1}')"
if [ "${expected}" != "${actual}" ]; then
  echo "Scarb checksum mismatch. Expected ${expected}, got ${actual}" >&2
  exit 1
fi
rm -rf "${INSTALL_ROOT}"
mkdir -p "${HOME}/.scarb"
tar -xzf "${tmpdir}/${SCARB_ARCHIVE}" -C "${HOME}/.scarb"
extracted="$(find "${HOME}/.scarb" -maxdepth 1 -type d -name "scarb-v${SCARB_VERSION}*" | head -n 1)"
mv "${extracted}" "${INSTALL_ROOT}"
if ! grep -q ".scarb/${SCARB_VERSION}/bin" "${HOME}/.bashrc" 2>/dev/null; then
  echo "export PATH=\"${INSTALL_ROOT}/bin:\$PATH\"" >> "${HOME}/.bashrc"
fi
export PATH="${INSTALL_ROOT}/bin:${PATH}"
scarb --version

echo "== Ethereum Foundry =="
if ! need_cmd forge; then
  curl -L https://foundry.paradigm.xyz -o /tmp/foundryup-install.sh
  bash /tmp/foundryup-install.sh
  export PATH="${HOME}/.foundry/bin:${PATH}"
  foundryup
fi
forge --version || true

echo "== Starknet Foundry / Starkup =="
echo "Running the official Starkup installer for Scarb/Starknet Foundry/dev tooling."
curl --proto '=https' --tlsv1.2 -sSf https://sh.starkup.sh -o /tmp/starkup.sh
sh /tmp/starkup.sh || {
  echo "Starkup did not finish cleanly. Read the error above, then rerun this script." >&2
  exit 1
}

echo "== Versions =="
scarb --version || true
cargo --version || true
forge --version || true
snforge --version || true
sncast --version || true

echo "Open a new shell or run: source ~/.bashrc"
