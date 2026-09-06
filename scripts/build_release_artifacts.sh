#!/usr/bin/env bash
# Build release artifacts for GitHub Releases (CI + local).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-${GITHUB_REF_NAME:-dev}}"
VERSION="${VERSION#v}"
DIST="$ROOT/dist"
BUILD="$DIST/lambda_build"
ZIP_NAME="soar-lambda-v${VERSION}.zip"

rm -rf "$DIST"
mkdir -p "$BUILD"

echo "==> Installing runtime deps into $BUILD"
python -m pip install -r "$ROOT/src/requirements.txt" -t "$BUILD" \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --only-binary=:all: \
  --upgrade \
  || python -m pip install -r "$ROOT/src/requirements.txt" -t "$BUILD" --upgrade

echo "==> Copying src/"
cp -a "$ROOT/src" "$BUILD/src"
find "$BUILD" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find "$BUILD" -type f -name '*.pyc' -delete 2>/dev/null || true

echo "==> Zipping $ZIP_NAME"
(
  cd "$BUILD"
  zip -r9 "$DIST/$ZIP_NAME" . -x '*.pyc' '*__pycache__*'
)

(
  cd "$DIST"
  sha256sum "$ZIP_NAME" > SHA256SUMS
)

cp "$ROOT/CHANGELOG.md" "$DIST/CHANGELOG.md"
cp "$ROOT/MIGRATION_v2.md" "$DIST/MIGRATION_v2.md"

echo "==> Artifacts:"
ls -lh "$DIST"
