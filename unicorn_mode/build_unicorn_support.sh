#!/bin/sh
#
# american fuzzy lop - Unicorn-Mode setup script
# ----------------------------------------------
#
# Written by Nathan Voss <njvoss99@gmail.com>
#
# Adapted from code by Andrew Griffiths <agriffiths@google.com> and
#                      Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2017 Battelle Memorial Institute. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# ----------------------------------------------------------------------------
# Unicorn 2.x setup (cross-platform: macOS and Linux).
#
# This installs a stock Unicorn Engine 2.x, which is what the emulation and
# coverage-recording workflow needs. Unicorn 2.x ships prebuilt wheels for
# macOS (Apple Silicon and Intel) and Linux, so there is nothing to compile.
#
# NOTE ON AFL-GUIDED FUZZING:
#   Driving these harnesses under afl-fuzz needs Unicorn instrumented to feed
#   AFL's coverage bitmap. That mechanism relies on the Linux fork server and
#   is Linux-only. The instrumented-Unicorn-v1 patches this script used to build
#   do not apply to Unicorn 2.x; the modern replacement is AFL++'s "unicornafl"
#   (https://github.com/AFLplusplus/AFLplusplus/tree/stable/unicorn_mode) on
#   Linux. On macOS you can emulate and record coverage, but not run afl-fuzz.
#
# The coverage workflow (drcov -> ghidra-aflcov / Lighthouse / Dragondance) is
# documented in COVERAGE.md and works anywhere Unicorn 2.x runs.

UNICORN_SPEC="unicorn>=2.0.0"
VENVDIR="$(cd "$(dirname "$0")" && pwd)/unicorn2-venv"

echo "================================================="
echo "afl-unicorn: Unicorn 2.x setup"
echo "================================================="
echo

OS="$(uname -s)"
echo "[*] Host OS: $OS"

# Locate a Python 3 interpreter.
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>/dev/null; then
      PY="$cand"
      break
    fi
  fi
done

if [ -z "$PY" ]; then
  echo "[-] Error: Python 3 not found. Install it first (macOS: 'brew install python')."
  exit 1
fi
echo "[+] Using Python: $($PY --version 2>&1) at $(command -v $PY)"

# Decide where to install Unicorn.
#   - Inside an active virtualenv: install there.
#   - Otherwise try a --user install; if the environment is externally managed
#     (PEP 668, common on modern macOS/Debian), fall back to a local venv.
RUN_PY="$PY"
ERRLOG="$(mktemp 2>/dev/null || echo /tmp/uc2_pip_err)"

install_into_local_venv() {
  echo "[*] Creating a local virtualenv at: $VENVDIR"
  "$PY" -m venv "$VENVDIR" || { echo "[-] Error: could not create venv."; exit 1; }
  "$VENVDIR/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1
  "$VENVDIR/bin/python" -m pip install "$UNICORN_SPEC" || { echo "[-] Error: pip install failed in venv."; exit 1; }
  RUN_PY="$VENVDIR/bin/python"
  USED_VENV=1
}

if [ -n "$VIRTUAL_ENV" ]; then
  echo "[*] Active virtualenv detected: $VIRTUAL_ENV"
  "$PY" -m pip install "$UNICORN_SPEC" || { echo "[-] Error: pip install failed."; exit 1; }
else
  echo "[*] Installing Unicorn 2.x ($UNICORN_SPEC)..."
  if "$PY" -m pip install --user "$UNICORN_SPEC" 2>"$ERRLOG"; then
    :
  elif grep -qi "externally-managed" "$ERRLOG"; then
    echo "[!] System Python is externally managed (PEP 668); using a local venv instead."
    install_into_local_venv
  else
    echo "[-] pip install failed:"
    cat "$ERRLOG"
    exit 1
  fi
fi
rm -f "$ERRLOG"

echo
echo "[*] Verifying the installation..."
if ! "$RUN_PY" -c "import unicorn; print('[+] Unicorn', unicorn.__version__, 'ready')"; then
  echo "[-] Error: Unicorn import failed after install."
  exit 1
fi

# Sanity-check that the sample harness emulates and records coverage.
HERE="$(cd "$(dirname "$0")" && pwd)"
SAMPLE="$HERE/samples/simple"
if [ -f "$SAMPLE/simple_test_harness.py" ] && [ -f "$SAMPLE/sample_inputs/sample1.bin" ]; then
  echo "[*] Running the simple sample to confirm emulation + coverage..."
  TMPCOV="$(mktemp 2>/dev/null || echo /tmp/uc2_sample.drcov)"
  if ( cd "$SAMPLE" && "$RUN_PY" simple_test_harness.py --coverage "$TMPCOV" ./sample_inputs/sample1.bin >/dev/null 2>&1 ) && [ -s "$TMPCOV" ]; then
    echo "[+] Sample emulated and wrote coverage successfully."
    rm -f "$TMPCOV"
  else
    echo "[!] Warning: sample run did not produce coverage. Unicorn is installed, but"
    echo "    check the harness manually (capstone is optional; only needed for -d)."
  fi
fi

echo
echo "[+] Done."
if [ -n "$USED_VENV" ]; then
  echo
  echo "    Unicorn was installed into a local virtualenv. Use it with:"
  echo "        source \"$VENVDIR/bin/activate\""
  echo "    or invoke harnesses as:"
  echo "        \"$VENVDIR/bin/python\" your_harness.py ..."
fi
echo
echo "    Next: see COVERAGE.md to record a drcov file and view it in Ghidra."
if [ "$OS" = "Linux" ]; then
  echo "    For afl-fuzz-driven fuzzing on Linux, use AFL++'s unicornafl (see header)."
fi
exit 0
