#!/usr/bin/env sh
set -eu
LITE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(dirname -- "$LITE_ROOT")"
BIN="$REPO_ROOT/work/annotation-free-invariants-20261021/binaries"
[ -f "$BIN/transfer_vulnerable.so" ] || { echo "Missing controlled vulnerable binary: $BIN/transfer_vulnerable.so" >&2; exit 1; }
[ -f "$BIN/transfer_patched.so" ] || { echo "Missing controlled patched binary: $BIN/transfer_patched.so" >&2; exit 1; }
JOB="$(curl --silent --show-error --fail -F "vulnerable=@$BIN/transfer_vulnerable.so" -F "patched=@$BIN/transfer_patched.so" http://127.0.0.1:8000/api/v1/analyses)"
ID="$(printf '%s' "$JOB" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
printf 'Created job: %s\n' "$ID"
while :; do
  STATUS="$(curl --silent --show-error --fail "http://127.0.0.1:8000/api/v1/analyses/$ID")"
  STAGE="$(printf '%s' "$STATUS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["stage"])')"
  STATE="$(printf '%s' "$STATUS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])')"
  printf 'Stage: %s\n' "$STAGE"
  [ "$STATE" = running ] || break
  sleep 1
done
printf '%s\n' "$STATUS" | python3 -c 'import json,sys;x=json.load(sys.stdin);print("Analysis status:",x.get("result",{}).get("analysis_status",x["status"]));v=x.get("result",{}).get("verification") or {};print("Vulnerable:",v.get("vulnerable",{}).get("status","not run"),"/",v.get("vulnerable",{}).get("solver_result","not run"));print("Patched:",v.get("patched",{}).get("status","not run"),"/",v.get("patched",{}).get("solver_result","not run"))'
printf 'HTML report: http://127.0.0.1:8000/api/v1/analyses/%s/report?format=html\n' "$ID"
