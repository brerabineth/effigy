#!/usr/bin/env bash
# effigy end-to-end suite. Every gate must pass; the counter is the receipt.
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
REPO=$(pwd)
PUB="${PUB_BIN:-}"
dotnet build -c Release > /dev/null 2>&1 || { echo "build failed"; exit 1; }
DEV="$REPO/bin/Release/net10.0/effigy"

ok()   { PASS=$((PASS+1)); }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
gate() { if [ "$1" = "0" ]; then ok; else bad "$2"; fi; }

echo "== e2e: effigy =="
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---------- fixtures ----------
$DEV forge "$WORK/fx" > /dev/null 2>&1
gate $? "forge runs"
[ -f "$WORK/fx/dropper-encoded.lnk" ] && ok || bad "fixture written"
$DEV forge "$WORK/fx2" > /dev/null 2>&1
DIFF=1
for f in "$WORK/fx"/*.lnk; do
  cmp -s "$f" "$WORK/fx2/$(basename "$f")" || DIFF=0
done
[ "$DIFF" = "1" ] && ok || bad "forge deterministic (byte-identical across runs)"

# ---------- selftest ----------
$DEV selftest > /dev/null 2>&1
gate $? "dev selftest"
if [ -n "$PUB" ]; then
  "$PUB" selftest > /dev/null 2>&1
  gate $? "published selftest"
fi

# ---------- verdict census ----------
declare -A WANT_EXIT=(
  [clean-note.lnk]=0 [clean-pdf-ref.lnk]=0 [clean-electron.lnk]=1
  [dropper-encoded.lnk]=10 [dropper-remote.lnk]=10 [unc-staging.lnk]=3
  [spoofed-icon.lnk]=10 [stomped.lnk]=10 [xor-decoder.lnk]=10
  [startup-persist.lnk]=3
)
declare -A WANT_BAND=(
  [clean-note.lnk]=clean [clean-pdf-ref.lnk]=clean [clean-electron.lnk]=watch
  [dropper-encoded.lnk]=hostile [dropper-remote.lnk]=hostile [unc-staging.lnk]=suspicious
  [spoofed-icon.lnk]=hostile [stomped.lnk]=hostile [xor-decoder.lnk]=hostile
  [startup-persist.lnk]=suspicious
)
for f in clean-note clean-pdf-ref clean-electron dropper-encoded dropper-remote \
         unc-staging spoofed-icon stomped xor-decoder startup-persist; do
  mkdir -p "$WORK/out"
  ( cd "$WORK" && "$DEV" scan "fx/$f.lnk" --json --quiet > "out/$f.json" )
  EC=$?
  [ "$EC" = "${WANT_EXIT[$f.lnk]}" ] && ok || bad "$f exit ($EC want ${WANT_EXIT[$f.lnk]})"
  BAND=$(python3 -c "import json;print(json.load(open('$WORK/out/$f.json'))['results'][0]['verdict'])")
  [ "$BAND" = "${WANT_BAND[$f.lnk]}" ] && ok || bad "$f band ($BAND want ${WANT_BAND[$f.lnk]})"
  N=$(python3 -c "import json;d=json.load(open('$WORK/out/$f.json'));print(d['tool']+str(d['results'][0]['score']>=0))")
  [ "$N" = "effigyTrue" ] && ok || bad "$f json shape"
done

# ---------- key findings present ----------
for spec in "dropper-encoded:args.decoded.lolbin:args.lolbin.encoded-switch:args.lolbin.hidden-window" \
            "dropper-remote:target.lolbin:args.http.remote-payload" \
            "unc-staging:target.remote:args.unc" \
            "spoofed-icon:spoof.document-name:icon.mismatch" \
            "stomped:timestamps.zeroed:env.var.exec" \
            "xor-decoder:args.payload.xor-decoder:overlay.script:encoded.hex-blob" \
            "startup-persist:target.startup:target.lolbin"; do
  name="${spec%%:*}"; ids="${spec#*:}"
  IFS=':' read -ra ID_ARR <<< "$ids"
  python3 - "$WORK/out/$name.json" "${ID_ARR[@]}" << 'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
have = {f["id"] for f in d["results"][0]["findings"]}
want = set(sys.argv[2:])
missing = want - have
sys.exit(0 if not missing else 1)
PYEOF
  gate $? "$name contains required findings (${ID_ARR[*]})"
done
# clean fixtures must have zero findings
CLEAN0=$(python3 -c "import json;print(len(json.load(open('$WORK/out/clean-note.json'))['results'][0]['findings'])+len(json.load(open('$WORK/out/clean-pdf-ref.json'))['results'][0]['findings']))")
[ "$CLEAN0" = "0" ] && ok || bad "clean fixtures have zero findings ($CLEAN0)"

# ---------- directory scan ----------
mkdir -p "$WORK/out"
( cd "$WORK" && $DEV scan fx --json --quiet > "out/dir.json" )
EC=$?
[ "$EC" = "10" ] && ok || bad "directory scan worst-case exit ($EC)"
NF=$(python3 -c "import json;print(json.load(open('$WORK/out/dir.json'))['files'])")
[ "$NF" = "10" ] && ok || bad "directory scan file count ($NF)"
WV=$(python3 -c "import json;print(json.load(open('$WORK/out/dir.json'))['verdict'])")
[ "$WV" = "hostile" ] && ok || bad "directory scan worst verdict ($WV)"

# idempotence
( cd "$WORK" && $DEV scan fx --json --quiet > "out/dir2.json" )
cmp -s "$WORK/out/dir.json" "$WORK/out/dir2.json" && ok || bad "scan idempotent (byte-identical rerun)"

# ---------- markdown + terminal ----------
( cd "$WORK" && $DEV scan fx/dropper-encoded.lnk --md --quiet > "out/r.md" ) 2>/dev/null
grep -q "^| severity | id | weight | detail |" "$WORK/out/r.md" && grep -q "args.decoded.lolbin" "$WORK/out/r.md" && ok || bad "md table + finding id"
( cd "$WORK" && $DEV scan fx/dropper-encoded.lnk --quiet > "out/t.txt" ) 2>/dev/null
grep -q "HOSTILE" "$WORK/out/t.txt" && grep -q "args.decoded.lolbin" "$WORK/out/t.txt" && ok || bad "terminal card content"

# ---------- stdin ----------
cat "$WORK/fx/dropper-remote.lnk" | $DEV scan - --json --quiet > "$WORK/out/stdin.json" 2>/dev/null
[ $? = "10" ] && ok || bad "stdin scan exit"
B1=$(python3 -c "import json;print(json.load(open('$WORK/out/stdin.json'))['results'][0]['verdict'])")
[ "$B1" = "hostile" ] && ok || bad "stdin verdict"

# ---------- gates ----------
$DEV scan "$WORK/fx/clean-note.lnk" --fail-on watch --quiet > /dev/null 2>&1
[ $? = "0" ] && ok || bad "fail-on watch passes on clean"
$DEV scan "$WORK/fx/clean-electron.lnk" --fail-on watch --quiet > /dev/null 2>&1
[ $? = "10" ] && ok || bad "fail-on watch escalates flagged"
$DEV scan "$WORK/fx/dropper-encoded.lnk" --min-score 200 --quiet > /dev/null 2>&1
[ $? = "2" ] && ok || bad "min-score below actual -> 2"
$DEV scan "$WORK/fx/dropper-encoded.lnk" --min-score 50 --quiet > /dev/null 2>&1
[ $? = "10" ] && ok || bad "min-score above actual -> normal exit"

# ---------- rules ----------
$DEV rules --json > "$WORK/out/rules.json" 2>/dev/null
N=$(python3 -c "import json;print(len(json.load(open('$WORK/out/rules.json'))))")
[ "$N" -ge 25 ] && ok || bad "rules catalog count ($N)"
python3 -c "
import json
rules = json.load(open('$WORK/out/rules.json'))
ids = [r['id'] for r in rules]
assert len(ids) == len(set(ids)), 'dup ids'
assert all(r['weight'] > 0 for r in rules), 'bad weight'
" && ok || bad "rules catalog sanity"

# ---------- show ----------
$DEV show "$WORK/fx/dropper-encoded.lnk" > "$WORK/out/show.txt" 2>/dev/null
grep -q "5e4c1a77-3f2b-4a1d-9c0e-1b2a3c4d5e6f" "$WORK/out/show.txt" && grep -q "tracker" "$WORK/out/show.txt" && ok || bad "show exposes tracker droids"
$DEV show "$WORK/fx/stomped.lnk" > "$WORK/out/show2.txt" 2>/dev/null
grep -q "environment-variable" "$WORK/out/show2.txt" && ok || bad "show lists environment block"
$DEV show "$WORK/fx/xor-decoder.lnk" > "$WORK/out/show3.txt" 2>/dev/null
grep -q "overlay" "$WORK/out/show3.txt" && ok || bad "show lists overlay"

# ---------- no-color ----------
NO_COLOR=1 $DEV scan "$WORK/fx/dropper-remote.lnk" --quiet > "$WORK/out/nc.txt" 2>/dev/null
(grep -q $'\x1b' "$WORK/out/nc.txt") && bad "NO_COLOR emitted escape" || ok

# ---------- truncation fuzz ----------
FUZZ_FAIL=0
for f in dropper-encoded stomped xor-decoder; do
  SIZE=$(stat -c %s "$WORK/fx/$f.lnk")
  for off in 4 10 24 37 52 68 91 114 150 210 290 400; do
    [ "$off" -ge "$SIZE" ] && continue
    head -c "$off" "$WORK/fx/$f.lnk" > "$WORK/cut.lnk"
    ERR=$(cd "$WORK" && $DEV scan cut.lnk --json --quiet 2>&1 > /dev/null)
    EC=$?
    case "$EC" in 0|1|3|10) ;; *) FUZZ_FAIL=1; echo "    fuzz $f@$off exit $EC: $ERR";; esac
    echo "$ERR" | grep -q "internal error" && { FUZZ_FAIL=1; echo "    fuzz $f@$off internal error"; } || true
  done
done
[ "$FUZZ_FAIL" = "0" ] && ok || bad "truncation fuzz (36+ cuts, structured verdicts only)"

# ---------- garbage input ----------
printf 'MZ\x90\x00not a shortcut at all, just filler bytes to push the parser around' > "$WORK/garbage.bin"
$DEV scan "$WORK/garbage.bin" --json --quiet > "$WORK/out/g.json" 2>/dev/null
case $? in 0|1|3|10) ok;; *) bad "garbage input exit";; esac

# ---------- dev == published parity ----------
if [ -n "$PUB" ]; then
  mkdir -p "$WORK/pfx"
  cp "$WORK/fx"/*.lnk "$WORK/pfx/"
  ( cd "$WORK" && "$PUB" scan pfx --json --quiet > "out/pub.json" )
  python3 - "$WORK/out/dir.json" "$WORK/out/pub.json" << 'PYEOF' && ok || bad "dev/publish JSON parity (modulo path prefix)"
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
na = {r["file"].split("/")[-1]: (r["verdict"], r["score"]) for r in a["results"]}
nb = {r["file"].split("/")[-1]: (r["verdict"], r["score"]) for r in b["results"]}
sys.exit(0 if na == nb else 1)
PYEOF
fi

# ---------- path / AI hygiene ----------
( cd "$WORK" && $DEV scan fx --md --quiet; $DEV scan fx --quiet; $DEV rules ) > "$WORK/out/hygiene.txt" 2>&1
( grep -q "/home/" "$WORK/out/hygiene.txt" || grep -qiE "claude|openai|assistant|language model" "$WORK/out/hygiene.txt" ) && bad "hygiene: host path or AI marker in output" || ok

echo "== e2e: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ] && exit 0 || exit 1
