#!/bin/sh
# Run a command inside a transient systemd user scope with memory, swap,
# CPU, task and wall-clock limits, so a runaway test (for example an
# endless read during mutation testing) is killed instead of exhausting
# the host. Fails closed: invalid limits or a scope that cannot be
# created mean nothing runs.
#
# Usage: scripts/safe-test.sh COMMAND [ARGS...]
#   e.g. scripts/safe-test.sh go test -race -count=1 ./...
# Limits can only be lowered, via environment variables:
#   KODIS_MEM_MAX   bytes with optional K/M/G suffix, at most 2G (default 2G)
#   KODIS_CPU_QUOTA percent, at most 200% (default 200%)
#   KODIS_TASKS_MAX at most 512 (default 512)
#   KODIS_TIMEOUT   seconds, at most 300 (default 300)
# Anything else (unset is fine; empty, zero, "infinity", signs, leading
# zeros, values above the maximum) is rejected with exit status 2.
set -eu

reject() {
	echo "safe-test.sh: $1" >&2
	exit 2
}

# positive N MAX NAME: N must be a decimal in 1..MAX without leading zeros.
positive() {
	case $1 in
	'' | *[!0-9]* | 0*) reject "$3 must be a positive integer, got '$1'" ;;
	esac
	[ "${#1}" -le 12 ] || reject "$3 is too large: '$1'"
	[ "$1" -le "$2" ] || reject "$3 may only be lowered (max $2), got '$1'"
}

mem=${KODIS_MEM_MAX-2G}
case $mem in
*K) n=${mem%K} mult=1024 ;;
*M) n=${mem%M} mult=1048576 ;;
*G) n=${mem%G} mult=1073741824 ;;
*) n=$mem mult=1 ;;
esac
positive "$n" 2147483648 KODIS_MEM_MAX
[ $((n * mult)) -le 2147483648 ] || reject "KODIS_MEM_MAX may only be lowered (max 2G), got '$mem'"

cpu=${KODIS_CPU_QUOTA-200%}
case $cpu in
*%) positive "${cpu%\%}" 200 KODIS_CPU_QUOTA ;;
*) reject "KODIS_CPU_QUOTA must be a percentage like 100%, got '$cpu'" ;;
esac

tasks=${KODIS_TASKS_MAX-512}
positive "$tasks" 512 KODIS_TASKS_MAX
timeout_s=${KODIS_TIMEOUT-300}
positive "$timeout_s" 300 KODIS_TIMEOUT

if [ "$#" -eq 0 ]; then
	echo "usage: $0 COMMAND [ARGS...]" >&2
	exit 2
fi
exec systemd-run --user --scope --quiet --collect \
	-p MemoryMax="$mem" \
	-p MemorySwapMax=0 \
	-p CPUQuota="$cpu" \
	-p TasksMax="$tasks" \
	-- timeout --kill-after=10 "$timeout_s" "$@"
