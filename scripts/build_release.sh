#!/usr/bin/env bash
# Release asset build: trimmed self-contained single-file binaries + SHA256SUMS.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' effigy.csproj)
OUT="${1:-dist/$VERSION}"
mkdir -p "$OUT"
for rid in linux-x64 linux-arm64 osx-arm64 win-x64; do
  dotnet publish -c Release -r "$rid" --self-contained \
    -p:PublishSingleFile=true -p:PublishTrimmed=true -o "$OUT/$rid" > /dev/null
  ext=""; [ "$rid" = "win-x64" ] && ext=".exe"
  mv "$OUT/$rid/effigy$ext" "$OUT/effigy-$VERSION-$rid$ext"
  rm -rf "$OUT/$rid"
done
( cd "$OUT" && sha256sum effigy-* > SHA256SUMS )
ls -la "$OUT"
echo "release assets in $OUT"
