#!/bin/sh
# Run a command inside a transient systemd user scope with memory, swap,
# CPU, task and wall-clock limits, so a runaway test (for example an
# endless read during mutation testing) is killed instead of exhausting
# the host. Fails closed: if the scope cannot be created, nothing runs.
#
# Usage: scripts/safe-test.sh COMMAND [ARGS...]
#   e.g. scripts/safe-test.sh go test -race -count=1 ./...
# Limits can be lowered (or raised) via environment variables:
#   KODIS_MEM_MAX (2G) KODIS_CPU_QUOTA (200%) KODIS_TASKS_MAX (512) KODIS_TIMEOUT (300, seconds)
set -eu
if [ "$#" -eq 0 ]; then
	echo "usage: $0 COMMAND [ARGS...]" >&2
	exit 2
fi
exec systemd-run --user --scope --quiet --collect \
	-p MemoryMax="${KODIS_MEM_MAX:-2G}" \
	-p MemorySwapMax=0 \
	-p CPUQuota="${KODIS_CPU_QUOTA:-200%}" \
	-p TasksMax="${KODIS_TASKS_MAX:-512}" \
	-- timeout --kill-after=10 "${KODIS_TIMEOUT:-300}" "$@"
