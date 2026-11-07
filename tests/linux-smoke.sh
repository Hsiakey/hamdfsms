#!/bin/bash
# Linux / WSL smoke test: build -> unit tests -> real daemon -> protocol -> inotify
# Run: bash tests/linux-smoke.sh   (needs gcc make libsqlite3-dev)
cd "$(dirname "$0")/.." || exit 1
PORT=19600
CW='hamster-linux-test-0123456789abcdef'
fail=0
ok()   { echo "  [PASS] $1"; }
bad()  { echo "  [FAIL] $1"; fail=$((fail+1)); }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

echo "=== 1. build POSIX branch"
make OS=linux clean >/dev/null 2>&1
timeout 600 make OS=linux all > /tmp/hamster-build.log 2>&1
BRC=$?
if [ "$BRC" != "0" ]; then
    echo "  build FAILED (rc=$BRC):"; grep -E 'error:' /tmp/hamster-build.log | head -10 | sed 's/^/    /'; exit 1
fi
NW=$(grep -c 'warning:' /tmp/hamster-build.log)
check "$NW" "build ok (rc=0), warnings=$NW"

echo
echo "=== 2. unit tests (POSIX path/thread/random branches)"
timeout 300 make OS=linux test > /tmp/hamster-test.log 2>&1
TRC=$?
grep -E "结果:|FAIL" /tmp/hamster-test.log | tail -2 | sed 's/^/    /'
if [ "$TRC" = "124" ]; then bad "unit tests HUNG (timeout) - possible infinite loop on POSIX"; else check "$TRC" "unit tests pass"; fi

echo
echo "=== 3. start real daemon"
TMP=$(mktemp -d)
mkdir -p "$TMP/mon"
printf 'hello' > "$TMP/mon/a.txt"
printf 'world' > "$TMP/mon/b.txt"
cp Hamsterd/hamsterd "$TMP/hamsterd" || { bad "hamsterd binary missing"; exit 1; }
cat > "$TMP/hamsterd.conf" <<EOF
monitor_path: $TMP/mon
ipv4_addr: 127.0.0.1
ipv4_addr_port: $PORT
codeword: $CW
require_auth: on
rescan_date: 0,0,0
verify_interval: 0
discovery_port: 0
log_level: info
log_dir: logs
EOF
( cd "$TMP" && exec ./hamsterd --console-log > out.log 2>&1 ) &
DPID=$!
i=0
while [ $i -lt 60 ]; do
    sleep 0.25
    (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
    i=$((i+1))
done
if ! (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
    bad "daemon not listening on :$PORT"; sed 's/^/    /' "$TMP/out.log"; kill $DPID 2>/dev/null; rm -rf "$TMP"; exit 1
fi
ok "daemon listening on 127.0.0.1:$PORT"
exec 3<>/dev/tcp/127.0.0.1/$PORT

# 按协议规定按 type 分流：事件可能与响应交错到达，读响应时要跳过事件行
resp() {
    local L
    while read -r -t 10 -u 3 L; do
        case "$L" in
            *'"type":"event"'*) continue ;;
            *) printf '%s' "$L"; return ;;
        esac
    done
}

printf '{"type":"request","id":"a","action":"stats"}\n' >&3
R1=$(resp)
case "$R1" in *unauthenticated*) ok "unauthenticated stats rejected (auth gate works on POSIX)" ;; *) bad "unauthenticated stats NOT rejected: $R1" ;; esac

printf '{"type":"request","id":"h","action":"hello","params":{"device_id":"smoke","codeword":"%s"}}\n' "$CW" >&3
R2=$(resp)
case "$R2" in *'"status":"ok"'*) ok "hello authenticated (pthreaded conn handling ok)" ;; *) bad "hello failed: $R2" ;; esac

printf '{"type":"request","id":"s","action":"stats"}\n' >&3
R3=$(resp)
case "$R3" in *'"total_files":2'*) ok "stats correct (startup scan indexed 2 files)" ;; *) bad "stats wrong: $R3" ;; esac

echo
echo "=== 4. inotify live monitoring"
printf 'new' > "$TMP/mon/c.txt"
sleep 2
printf '{"type":"request","id":"s2","action":"stats"}\n' >&3
R4=$(resp)
case "$R4" in *'"total_files":3'*) ok "new file caught by inotify and indexed" ;; *) bad "inotify missed new file: $R4" ;; esac

printf '{"type":"request","id":"l","action":"list","params":{"path":"."}}\n' >&3
R5=$(resp)
case "$R5" in *a.txt*) ok "list returns directory content" ;; *) bad "list wrong: $R5" ;; esac

exec 3<&-
kill $DPID 2>/dev/null
sleep 1
echo
echo "=== 5. logging"
if [ -f "$TMP/logs/hamsterd.log" ]; then
    ok "log written under logs/ (outside monitor dir, no self-excitation)"
    tail -4 "$TMP/logs/hamsterd.log" | sed 's/^/    /'
else
    bad "no log generated"
fi
rm -rf "$TMP"
echo
if [ "$fail" = "0" ]; then echo "  LINUX/WSL ALL PASS"; exit 0; fi
echo "  FAILED $fail"; exit 1