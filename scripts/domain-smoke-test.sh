#!/usr/bin/env bash
# Probes a single domain with greasy and conn (over TCP and QUIC), then feeds
# any ECHConfigList either returns through dech. Used by `make test-domains`
# to fuzz the tool binaries across a large sample of real-world domains.
#
# This is a crash/robustness check, not a correctness check: ECH rejections,
# timeouts, refused connections etc. are all expected outcomes for most
# domains and are not reported. Only two kinds of problems are reported:
#   CRASH      greasy/conn exited with an unexpected code, or panicked
#   DECH-FAIL  dech could not decode a config greasy/conn itself emitted
#
# Usage: domain-smoke-test.sh <bin-dir> <static-ech-config-b64> <domain>
set -u

BIN_DIR=$1
STATIC_CONFIG=$2
DOMAIN=$3

fail=0

# run_one <label> <tool> <args...>
run_one() {
	local label=$1 bin=$2
	shift 2
	local outf errf
	outf=$(mktemp)
	errf=$(mktemp)

	"$BIN_DIR/$bin" "$@" >"$outf" 2>"$errf"
	local code=$?

	if [ "$code" -ne 0 ] && [ "$code" -ne 1 ]; then
		echo "CRASH $label $DOMAIN exit=$code: $(tail -1 "$errf")"
		fail=1
	elif grep -qE 'panic:|fatal error:' "$errf"; then
		echo "CRASH $label $DOMAIN (panic): $(grep -m1 -E 'panic:|fatal error:' "$errf")"
		fail=1
	elif [ "$code" -eq 0 ] && [ -s "$outf" ]; then
		local dechout decherr dcode
		dechout=$(mktemp)
		decherr=$(mktemp)
		"$BIN_DIR/dech" --ech-config "$(cat "$outf")" >"$dechout" 2>"$decherr"
		dcode=$?
		if [ "$dcode" -ne 0 ]; then
			echo "DECH-FAIL $label $DOMAIN exit=$dcode: $(tail -1 "$decherr")"
			fail=1
		fi
		rm -f "$dechout" "$decherr"
	fi

	rm -f "$outf" "$errf"
}

run_one greasy-tcp greasy tcp "$DOMAIN" --format b64
run_one greasy-quic greasy quic "$DOMAIN" --format b64
run_one conn-tcp echconn tcp "$DOMAIN" --ech-config "$STATIC_CONFIG" --format b64
run_one conn-quic echconn quic "$DOMAIN" --ech-config "$STATIC_CONFIG" --format b64

echo "DONE $DOMAIN"
exit $fail
