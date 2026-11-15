#!/bin/bash
###############################################################################
# mocke2e.sh — L2 E2E: boot the REAL delivered bundle (--no-embedded) under a
# REAL Xvfb + twm, pointed at the localhost JSON-RPC mock (NO daemon at all),
# and assert the privacy-bundle's connect UX end-to-end.
#
# This is the docs/TESTING.md L2 lane specialised for the MOCK backend: where
# uxmatrix.sh launches the bundle's embedded zclassicd against an isolated chain,
# this lane launches the bundle with --no-embedded against tests/mock/mockrpc.py.
# That exercises the REAL ConnectionLoader handshake (autoDetectZClassicConf ->
# refreshZClassicdState getinfo -> classifyForeignDaemon getbootstrapinfo ->
# doRPCSetConnection -> "Payment UI now ready!") on the real xcb window path,
# with ZERO product change and ZERO daemon (instant, deterministic, no chain).
#
# Runs INSIDE the proot glibc-2.31 chroot (HOME=/zhome), invoked exactly like
# shot.sh:
#     /home/rhett/zclbuild/prun bash -c 'HOME=/zhome bash /src/wallet/tests/e2e/mocke2e.sh'
# (run.sh's EXTRA_BINDS supply /zhome; if you invoke prun directly you must bind a
#  writable /zhome yourself — see the EXTRA_BINDS note at the bottom.)
#
# ASSERTS (one scenario, funded-synced):
#   (a) the "ZclWallet v..." main window MAPS under real xcb (xwininfo).
#   (b) the GUI reaches connected/ready against the MOCK — "Payment UI now ready"
#       in the GUI log (proves the full getinfo+getbootstrapinfo handshake ran
#       against the mock, not a daemon).
#   (c) a clean WM_DELETE quit (the bundled /build/wmclose helper) exits the
#       process WITHOUT hang (bounded wait), exit status recorded.
#   plus: a screenshot of the connected window is captured.
#
# SAFETY (peer#1 is a LIVE SYSTEM zclassicd on this host; datadir
# /home/rhett/.zclassic) — REUSED FROM shot.sh EXACTLY:
#   * Isolated datadir /zhome/.zclassic on an ISOLATED RPC port 18992 — never the
#     default 8023/8033/8232 that peer#1 binds, and never a P2P listen at all
#     (the GUI is --no-embedded, so no node ever starts).
#   * Teardown kills ONLY recorded pids we spawned (GUI, mock, Xvfb, twm) plus any
#     process whose cmdline contains "datadir=/zhome/.zclassic". NEVER a bare
#     'zclassicd' match. With --no-embedded there is in fact no daemon to reap, but
#     the datadir-scoped sweep is kept belt-and-suspenders, identical to shot.sh.
#   * /home/rhett/.zclassic is NEVER read or written. No params are needed (no
#     daemon), so we do not even touch /zp.
#   * The mock is matched/killed by its RECORDED pid only — never by name.
###############################################################################
set -uo pipefail

# ---- committed constants (match shot.sh / uxmatrix.sh conventions) -----------
DISP=":99"
APP_VERSION="${APP_VERSION:-2.1.2-beta5}"
BUN="/src/wallet/artifacts/linux-zclwallet-v${APP_VERSION}"
MOCK="/src/wallet/tests/mock/mockrpc.py"
SCENARIO="${MOCK_SCENARIO:-funded-synced}"
RPCPORT="${RPCPORT:-18992}"            # ISOLATED — never peer#1's 8023/8232
DD="/zhome/.zclassic"
# The bundle's Qt org/app log path (must match QCoreApplication setup so we read
# the same log it writes). Same path uxmatrix.sh uses.
LOGDIR="/zhome/.local/share/zcl-qt-wallet-org/zcl-qt-wallet"
GUILOG="$LOGDIR/zcl-qt-wallet.log"
OUT="${OUT:-/zhome/mocke2e-shots}"
MOCK_LOG="${MOCK_LOG:-/zhome/mockrpc.requests.log}"

# Timing knobs (seconds). The mock answers instantly, so connect is fast; these
# are generous ceilings, not expected durations.
MAP_MAXT="${MAP_MAXT:-60}"             # window must map within this
READY_MAXT="${READY_MAXT:-60}"         # "Payment UI now ready" within this
CLOSE_TIMEOUT_S="${CLOSE_TIMEOUT_S:-30}"   # clean-close must finish within this

# Recorded child pids — cleanup never has to guess (shot.sh discipline).
XPID=""; WMPID=""; GPID=""; MOCKPID=""

RC=0
log(){ printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
fail(){ log "FAIL: $*"; RC=1; }
hr(){ printf -- '----------------------------------------------------------------------\n'; }

# ---- datadir-scoped + recorded-pid teardown ONLY (shot.sh semantics) ---------
cleanup() {
  local p
  # 1) the GUI we launched (recorded pid)
  [ -n "$GPID" ]   && kill    "$GPID"   2>/dev/null || true
  sleep 1
  [ -n "$GPID" ]   && kill -9 "$GPID"   2>/dev/null || true
  # 2) any process bound to the ISOLATED datadir (none with --no-embedded, but
  #    kept identical to shot.sh; NEVER a bare 'zclassicd' name match).
  for p in $(pgrep -af "datadir=$DD" 2>/dev/null | grep -F "$DD" | awk '{print $1}'); do
    kill    "$p" 2>/dev/null || true
  done
  sleep 1
  for p in $(pgrep -af "datadir=$DD" 2>/dev/null | grep -F "$DD" | awk '{print $1}'); do
    kill -9 "$p" 2>/dev/null || true
  done
  # 3) the mock — by RECORDED pid only (never by name). Prefer its clean
  #    GET /__shutdown if the pid is still up, then hard-stop as a backstop.
  if [ -n "$MOCKPID" ] && kill -0 "$MOCKPID" 2>/dev/null; then
    kill -TERM "$MOCKPID" 2>/dev/null || true
    for _ in 1 2 3; do kill -0 "$MOCKPID" 2>/dev/null || break; sleep 1; done
    kill -9 "$MOCKPID" 2>/dev/null || true
  fi
  # 4) our X stack (recorded pids only)
  [ -n "$WMPID" ] && kill -9 "$WMPID" 2>/dev/null || true
  [ -n "$XPID" ]  && kill -9 "$XPID"  2>/dev/null || true
  rm -f "/tmp/.X11-unix/X99" "/tmp/.X99-lock" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---- find the wallet window id (title begins "ZclWallet v..." — main.cpp:293) -
wallet_window_line() {
  DISPLAY="$DISP" xwininfo -root -tree 2>/dev/null | grep -i 'ZclWallet' | head -1 | sed 's/^ *//'
}
wallet_window_id() {
  DISPLAY="$DISP" xwininfo -root -tree 2>/dev/null | grep -i 'ZclWallet' \
    | grep -oE '0x[0-9a-fA-F]+' | head -n1
}

# ============================================================================ #
# 0. PRE-FLIGHT
# ============================================================================ #
hr
[ -x "$BUN" ] || { log "ABORT: bundle not found/executable: $BUN"; exit 2; }
[ -f "$MOCK" ] || { log "ABORT: mock not found: $MOCK"; exit 2; }
[ -x /build/wmclose ] || { log "ABORT: /build/wmclose missing (clean-close helper)"; exit 2; }
SHA="$(sha256sum "$BUN" | cut -d' ' -f1)"
log "bundle=$BUN"
log "bundle sha256=$SHA"
# We deliberately do NOT sha-gate against the .sha256 sidecar here: this L2 lane's
# job is to boot the CURRENT delivered build against the mock. (uxmatrix.sh owns
# the stale-build sha-gate for the daemon-backed lanes.) The sha is printed for
# the record.
mkdir -p "$OUT" "$DD" "$LOGDIR"
rm -f "$OUT"/*.png 2>/dev/null || true
: > "$MOCK_LOG"
: > "$GUILOG"     # fresh GUI log so our state-scan only sees this run

# ============================================================================ #
# 1. ISOLATED CONF — point the --no-embedded bundle at the MOCK
# ============================================================================ #
# rpcuser/rpcpassword are required for the bundle to assemble Basic auth; the mock
# IGNORES them. rpcport=18992 is what autoDetectZClassicConf() reads (connection.cpp
# :2328). NO daemon=1 (we do not want the GUI to think it owns a daemon), NO port=
# / bootstrap= / addnode= (no node ever launches).
printf 'rpcuser=t\nrpcpassword=t\nrpcport=%s\n' "$RPCPORT" > "$DD/zclassic.conf"
log "wrote $DD/zclassic.conf (rpcport=$RPCPORT, auth ignored by mock)"

# Pre-seed QSettings one-shots so the connect path is a clean, unambiguous
# single-window flow (TESTING.md L2: "pre-seed QSettings one-shots"):
#   * ez/onboardingShown=true  -> no first-run onboarding card.
#   * options/walletbackedup=true -> the funded-synced scenario has a positive,
#       fully-synced balance, which legitimately FIRES the F1 backup-nag QMessageBox
#       (a nested modal exec()). That nag is its OWN L1 test (F1/F3/F4); here it
#       would just put a second, modal top-level in front of the main window and
#       muddy the clean-close assertion. Marking the wallet already-backed-up
#       suppresses it (mainwindow.cpp:1159) so close (c) exercises the MAIN window's
#       closeEvent -> graceful quit, exactly what this lane is asserting.
QCONF_DIR="/zhome/.config/zcl-qt-wallet-org"
mkdir -p "$QCONF_DIR"
printf '[ez]\nonboardingShown=true\n\n[options]\nwalletbackedup=true\n' > "$QCONF_DIR/zcl-qt-wallet.conf"
log "seeded QSettings: ez/onboardingShown=true, options/walletbackedup=true (suppress F1 nag for an unambiguous clean-close)"

# ============================================================================ #
# 2. START THE MOCK (inside the chroot -> shares loopback with the GUI)
# ============================================================================ #
hr
log "starting mock: scenario=$SCENARIO port=$RPCPORT log=$MOCK_LOG"
MOCK_PORT="$RPCPORT" MOCK_SCENARIO="$SCENARIO" MOCK_LOG="$MOCK_LOG" \
  python3 "$MOCK" >/zhome/mock.stderr.log 2>&1 &
MOCKPID=$!
# Poll the mock's health endpoint until it answers (never a blind sleep).
mock_up=no
for i in $(seq 1 30); do
  if ! kill -0 "$MOCKPID" 2>/dev/null; then
    log "mock died during startup — log:"; sed 's/^/  mock| /' /zhome/mock.stderr.log 2>/dev/null
    break
  fi
  # bash /dev/tcp probe + a GET / health read (python is already up if it answers).
  if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$RPCPORT; printf 'GET / HTTP/1.0\r\n\r\n' >&3; grep -q '\"ok\": true' <&3" 2>/dev/null; then
    mock_up=yes; break
  fi
  sleep 0.5
done
[ "$mock_up" = yes ] || { fail "mock never became healthy on 127.0.0.1:$RPCPORT"; sed 's/^/  mock| /' /zhome/mock.stderr.log 2>/dev/null; exit 1; }
log "mock healthy on 127.0.0.1:$RPCPORT (pid=$MOCKPID)"

# ============================================================================ #
# 3. BOOT Xvfb :99 + twm (REAL xcb path)
# ============================================================================ #
hr
rm -f "/tmp/.X11-unix/X99" "/tmp/.X99-lock" 2>/dev/null || true
Xvfb "$DISP" -screen 0 1366x900x24 -nolisten tcp >/zhome/xvfb.log 2>&1 & XPID=$!
up=no
for i in $(seq 1 40); do
  kill -0 "$XPID" 2>/dev/null || { log "Xvfb died"; sed 's/^/  xvfb| /' /zhome/xvfb.log; break; }
  DISPLAY="$DISP" xwininfo -root >/dev/null 2>&1 && { up=yes; break; }
  sleep 0.5
done
[ "$up" = yes ] || { fail "Xvfb never came up"; exit 1; }
# twm is BEST-EFFORT: the proot rootfs ships NO X11 bitmap fonts, so twm exits on
# its first fontset open ("unable to open fontset -adobe-helvetica-..."). That is
# harmless here — the Qt/xcb window still MAPS and RENDERS (Qt uses its own bundled
# font engine, not X11 server fonts), and `wmclose` delivers WM_DELETE_WINDOW
# directly to the window id with or without a running WM. So we start twm for
# realism but NEVER fail the run on its death (same tolerance shot.sh relies on).
DISPLAY="$DISP" twm >/zhome/twm.log 2>&1 & WMPID=$!
sleep 1
if kill -0 "$WMPID" 2>/dev/null; then
  log "Xvfb=$XPID twm=$WMPID root-window OK"
else
  WMPID=""
  log "Xvfb=$XPID root-window OK; twm exited (no X11 fonts in chroot) — continuing WM-less (window still maps; wmclose sends WM_DELETE directly)"
  sed 's/^/  twm| /' /zhome/twm.log 2>/dev/null
fi

# ============================================================================ #
# 4. LAUNCH the delivered bundle with --no-embedded against the mock
#    (QT_QPA unset + DISPLAY set => the bundle auto-selects xcb, main.cpp:417)
# ============================================================================ #
hr
cd /zhome
env DISPLAY="$DISP" HOME=/zhome "$BUN" --no-embedded >/zhome/gui.log 2>&1 & GPID=$!
log "GUI pid=$GPID launched (--no-embedded -> mock on $RPCPORT)"

# ---- (a)+(b): wait for the window to MAP and the connect banner to print -----
mapped=0; ready=0; window_line=""
DEADLINE=$(( MAP_MAXT > READY_MAXT ? MAP_MAXT : READY_MAXT ))
for i in $(seq 1 "$DEADLINE"); do
  if ! kill -0 "$GPID" 2>/dev/null; then
    wait "$GPID"; ec=$?
    fail "GUI exited early at t+${i}s (exit=$ec) — never reached ready"
    break
  fi
  if [ "$mapped" -eq 0 ]; then
    wl="$(wallet_window_line)"
    if [ -n "$wl" ]; then
      mapped=1; window_line="$wl"
      log "t=${i}s MAPPED: $wl"
      DISPLAY="$DISP" import -window root "$OUT/mapped.png" 2>/dev/null || true
    fi
  fi
  # NB: the bundle prints "Payment UI now ready!" to STDOUT (-> /zhome/gui.log),
  # NOT to the Qt org log ($GUILOG). The org log instead carries the connect trail
  # ("Attached to a ZClassic node already running", "connect ok: ... teardown").
  # We grep BOTH so the assertion is robust to either sink.
  if [ "$ready" -eq 0 ] && \
     { grep -qa "Payment UI now ready" /zhome/gui.log 2>/dev/null || \
       grep -qa "connect ok:" "$GUILOG" 2>/dev/null; }; then
    ready=1
    log "t=${i}s GUI reached READY (connected to MOCK: 'Payment UI now ready')"
    DISPLAY="$DISP" import -window root "$OUT/connected.png" 2>/dev/null || true
  fi
  # Surface the staged-banner transitions for the run log (best-effort). The
  # connect trail is in the Qt org log; the final ready banner is on stdout.
  st=$( { grep -aoE "Step [0-9] of 3:[^\"]*|zclassicd is online|Attached to a ZClassic node[^\"]*|Pre-existing ZClassic node[^\"]*" \
            "$GUILOG" 2>/dev/null; \
          grep -aoE "Payment UI now ready" /zhome/gui.log 2>/dev/null; } | tail -n1)
  [ -n "$st" ] && [ "$st" != "${prev:-}" ] && { log "   [t+${i}s] $st"; prev="$st"; }
  [ "$mapped" -eq 1 ] && [ "$ready" -eq 1 ] && break
  sleep 1
done

# Take a final screenshot of whatever is on screen regardless.
DISPLAY="$DISP" import -window root "$OUT/final.png" 2>/dev/null || true

[ "$mapped" -eq 1 ] || fail "window never MAPPED within ${MAP_MAXT}s (assert a)"
[ "$ready"  -eq 1 ] || fail "GUI never reached 'Payment UI now ready' against the mock within ${READY_MAXT}s (assert b)"

# ============================================================================ #
# 5. (c) CLEAN CLOSE via WM_DELETE (the bundled wmclose helper) — bounded.
#    We WM_DELETE every mapped "ZclWallet*" top-level (the connect splash, an
#    ApplicationModal QDialog titled exactly "ZclWallet", can swallow a close of
#    the main window during a slow connect; with the mock connect is instant, so
#    this is normally just the main window). Whichever is correct gets closed.
# ============================================================================ #
hr
clean_close_exit="na"
if kill -0 "$GPID" 2>/dev/null; then
  DISPLAY="$DISP" import -window root "$OUT/before_close.png" 2>/dev/null || true
  wids="$(DISPLAY="$DISP" xwininfo -root -tree 2>/dev/null | grep -i 'ZclWallet' | grep -oE '0x[0-9a-fA-F]+')"
  if [ -z "$wids" ]; then
    fail "could not re-read any ZclWallet window id for clean-close (assert c)"
  else
    log "clean-close — WM_DELETE_WINDOW to: $(echo $wids | tr '\n' ' ')"
    # Iterative close: re-send WM_DELETE each second to EVERY remaining ZclWallet
    # top-level until the process exits. This is robust to a stray modal (e.g. if
    # a future scenario leaves a QMessageBox up): closing the modal first lets the
    # next pass reach the now-unblocked main window. With walletbackedup seeded
    # there is normally just the one main window and it quits on the first pass.
    closed=no
    for i in $(seq 1 "$CLOSE_TIMEOUT_S"); do
      if ! kill -0 "$GPID" 2>/dev/null; then
        wait "$GPID"; clean_close_exit=$?; closed=yes
        log "process exited after WM_DELETE — exit=$clean_close_exit (t+${i}s)"
        break
      fi
      cur="$(DISPLAY="$DISP" xwininfo -root -tree 2>/dev/null | grep -i 'ZclWallet' | grep -oE '0x[0-9a-fA-F]+')"
      for wid in $cur; do
        DISPLAY="$DISP" /build/wmclose "$wid" >>/zhome/wmclose.log 2>&1 || true
      done
      sleep 1
    done
    if [ "$closed" != yes ]; then
      fail "did NOT exit within ${CLOSE_TIMEOUT_S}s after WM_DELETE (hung teardown — assert c)"
    elif [ "$clean_close_exit" -ne 0 ]; then
      # A WM_DELETE-driven Qt closeEvent should exit 0. Non-zero is a real defect,
      # but for THIS lane (no daemon, --no-embedded) the only requirement the task
      # states is "exits without hang"; we still record + flag a non-zero code.
      log "NOTE: clean close exited non-zero (exit=$clean_close_exit)"
    fi
    GPID=""
  fi
else
  log "GUI already gone before clean-close step (recorded above)"
fi

# ============================================================================ #
# 6. EVIDENCE + VERDICT
# ============================================================================ #
hr
log "mock saw $(wc -l < "$MOCK_LOG" 2>/dev/null || echo 0) RPC request(s); methods:"
grep -oE '"method":"[a-z_]+"' "$MOCK_LOG" 2>/dev/null | sort | uniq -c | sed 's/^/   /'
log "screenshots:"; ls -la "$OUT" 2>/dev/null | sed 's/^/   /'

# Tear down our stack now (the EXIT trap also runs, idempotently).
cleanup
XPID=""; WMPID=""; GPID=""; MOCKPID=""

# Final, machine-parseable verdict line + the mapped-window line (task requirement).
hr
if [ "$RC" -eq 0 ]; then VERDICT=PASS; else VERDICT=FAIL; fi
printf 'MOCKE2E scenario=%s sha256=%s window_mapped=%s ready=%s clean_close_exit=%s -> %s\n' \
  "$SCENARIO" "$SHA" "$mapped" "$ready" "$clean_close_exit" "$VERDICT"
printf 'MAPPED_WINDOW: %s\n' "${window_line:-<none>}"
log "tail gui.log:"; tail -20 /zhome/gui.log 2>/dev/null | sed 's/^/  gui| /'
exit "$RC"

###############################################################################
# DIRECT INVOCATION (without run.sh supplying /zhome):
#   RUNHOME="$(mktemp -d)"
#   EXTRA_BINDS="-b $RUNHOME:/zhome" /home/rhett/zclbuild/prun \
#     bash -c 'HOME=/zhome bash /src/wallet/tests/e2e/mocke2e.sh'
#   rm -rf "$RUNHOME"
###############################################################################
