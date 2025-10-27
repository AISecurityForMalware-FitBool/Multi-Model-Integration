#!/bin/bash
set -euo pipefail

BUCKET=$1
KEY=$2
FILENAME=$(basename "$KEY")
BASENAME="${FILENAME%.*}"

WORKDIR=/opt/work
OUTDIR=/opt/out
PROJECT_DIR=/opt/ghidra_proj
GHIDRA_HOME=/opt/ghidra_11.4.2_PUBLIC

rm -rf "$WORKDIR" "$OUTDIR" "$PROJECT_DIR"
mkdir -p "$WORKDIR" "$OUTDIR" "$PROJECT_DIR"

aws s3 cp "s3://$BUCKET/$KEY" "$WORKDIR/input.exe"

"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PROJECT_DIR" FargateProj \
  -import "$WORKDIR/input.exe" \
  -scriptPath /opt/scripts \
  -postScript export_asm.py \
  -deleteProject \
  -analysisTimeoutPerFile 60

# === 고정된 Ghidra 결과 파일 경로 ===
ASM_FILE="$OUTDIR/input.asm"

if [[ -f "$ASM_FILE" ]]; then
    echo "[+] Found ASM output. Uploading..."
    aws s3 cp "$ASM_FILE" "s3://$BUCKET/Ghidra_ASM/${BASENAME}.asm"
    echo "[✓] Uploaded to s3://$BUCKET/Ghidra_ASM/${BASENAME}.asm"
else
    echo "[!] ASM file not found: $ASM_FILE"
    cat "$OUTDIR"/*.log || true
    exit 1
fi
