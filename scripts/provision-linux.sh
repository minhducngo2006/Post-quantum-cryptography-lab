#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NATIVE_DIR="$ROOT/.native"
SOURCE_DIR="$NATIVE_DIR/src"
BUILD_DIR="$NATIVE_DIR/build-linux-x86_64"
PREFIX="$NATIVE_DIR/liboqs"
LIBOQS_TAG="0.16.0"
LIBOQS_COMMIT="5a1a854b0dc9f2141bdc771c555ee60c37950183"
BUILD_JOBS=2

for tool in git cmake gcc make uv; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Missing required build tool: %s\n' "$tool" >&2
    exit 1
  fi
done

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf 'This provisioning script supports Linux x86_64 only.\n' >&2
  exit 1
fi

mkdir -p "$NATIVE_DIR"
uv sync --locked --extra dev --project "$ROOT"

if [[ -d "$SOURCE_DIR/.git" ]]; then
  CURRENT_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
  if [[ "$CURRENT_COMMIT" != "$LIBOQS_COMMIT" ]]; then
    printf 'Existing liboqs source is not the pinned commit; refusing to overwrite it.\n' >&2
    exit 1
  fi
elif [[ -e "$SOURCE_DIR" ]]; then
  printf 'Native source path exists but is not a Git checkout; refusing to overwrite it.\n' >&2
  exit 1
else
  git clone --depth 1 --branch "$LIBOQS_TAG" \
    https://github.com/open-quantum-safe/liboqs.git "$SOURCE_DIR"
fi

CURRENT_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$CURRENT_COMMIT" != "$LIBOQS_COMMIT" ]]; then
  printf 'liboqs tag resolved to unexpected commit: %s\n' "$CURRENT_COMMIT" >&2
  exit 1
fi

cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_sha2_192s;SIG_slh_dsa_pure_sha2_256s" \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DOQS_ENABLE_SIG_ML_DSA=ON \
  -DOQS_ENABLE_SIG_SLH_DSA=ON \
  -DOQS_ENABLE_KEM_NTRU=OFF \
  -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
  -DOQS_ENABLE_SIG_FALCON=OFF \
  -DOQS_ENABLE_SIG_STFL_LMS=OFF \
  -DOQS_ENABLE_SIG_STFL_XMSS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX"

cmake --build "$BUILD_DIR" --parallel "$BUILD_JOBS"
cmake --install "$BUILD_DIR"

OQS_INSTALL_PATH="$PREFIX" uv run --locked --project "$ROOT" python "$ROOT/scripts/check-native.py"
