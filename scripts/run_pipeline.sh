#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
PCAP_DIR="$ROOT/data/raw/scenario-01-neris/pcap"
PCAP="$PCAP_DIR/botnet-capture-20110810-neris.pcap"
FLOW="$ROOT/data/raw/scenario-01-neris/labeled-flows/capture20110810.binetflow"
ZEEK_DIR="$ROOT/data/processed/scenario-01-neris/zeek"
OUTPUT="$ROOT/reports/week1/generated"

[[ -x "$PYTHON" ]] || { echo "Missing Python: $PYTHON" >&2; exit 1; }
[[ -s "$PCAP" ]] || { echo "Missing PCAP: $PCAP" >&2; exit 1; }
[[ -s "$FLOW" ]] || { echo "Missing labeled flows: $FLOW" >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker CLI missing" >&2; exit 1; }
mkdir -p "$ZEEK_DIR" "$OUTPUT"

echo "[1/7] Capture provenance"
sha256sum "$PCAP" "$FLOW" > "$OUTPUT/input_checksums.txt"
docker run --rm zeek/zeek:lts zeek --version > "$OUTPUT/zeek_version.txt" 2>&1
docker image inspect zeek/zeek:lts --format '{{.Id}} {{json .RepoDigests}}' > "$OUTPUT/zeek_image_identity.txt"
"$PYTHON" --version > "$OUTPUT/python_version.txt" 2>&1
"$PYTHON" -m pip freeze > "$OUTPUT/python_dependencies.txt"

echo "[2/7] Zeek JSON logs"
if [[ ! -s "$ZEEK_DIR/conn.log" || ! -s "$ZEEK_DIR/http.log" ]]; then
    docker run --rm \
      -v "$PCAP_DIR:/pcap:ro" \
      -v "$ZEEK_DIR:/logs" \
      -w /logs \
      zeek/zeek:lts \
      zeek -C -r /pcap/botnet-capture-20110810-neris.pcap 'LogAscii::use_json=T'
else
    echo "Existing conn.log and http.log found; using cached logs"
fi

echo "[3/7] Connection, protocol, port, volume analytics"
"$PYTHON" src/analysis/traffic_stats.py

echo "[4/7] Repeated-connection / beaconing analytics"
"$PYTHON" src/analysis/beaconing_prototype.py

echo "[5/7] HTTP candidate evidence and POST intervals"
"$PYTHON" src/analysis/http_c2_evidence.py

echo "[6/7] Ground-truth label summaries"
"$PYTHON" src/analysis/ground_truth_prep.py

echo "[7/7] HTTP C2 Argus–Zeek matching and exception check"
"$PYTHON" src/analysis/http_c2_flow_alignment.py
"$PYTHON" src/analysis/http_c2_exception_probe.py

echo "===== WEEK 1 PIPELINE COMPLETED ====="
echo "Outputs: $OUTPUT"
