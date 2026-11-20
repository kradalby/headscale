#!/usr/bin/env bash
# Soaks the property tests: every property in rotation, fresh seeds, deep
# budgets, several workers, until the time is up or a file named STOP appears
# in the output directory. See hscontrol/policy/policymodel/README.md.
#
# usage: tools/pbt-soak.sh [worktree=.] [hours=8] [workers=6]
# PBT_SOAK_OUT (default <worktree>/pbt-soak) takes results.tsv, fails.log and
# the log of each failed run; PBT_SOAK_BIN takes the test binaries, built once.
set -uo pipefail

WT=$(cd "${1:-.}" && pwd) || exit 1
HOURS=${2:-8}
WORKERS=${3:-6}
OUT=${PBT_SOAK_OUT:-$WT/pbt-soak}
BIN=${PBT_SOAK_BIN:-${TMPDIR:-/tmp}/pbt-soak-bin}
RUN=$BIN/run
mkdir -p "$OUT/fails" "$BIN" "$RUN"
END=$(($(date +%s) + HOURS * 3600))

declare -A PKG=([mapper]=hscontrol/mapper [v2]=hscontrol/policy/v2 [state]=hscontrol/state)

cd "$WT" || exit 1
git rev-parse HEAD >"$OUT/commit"
: >>"$OUT/results.tsv"

for k in "${!PKG[@]}"; do
	[ -x "$BIN/$k.test" ] || go test -c -o "$BIN/$k.test" "./${PKG[$k]}" || {
		echo "build failed: $k"
		exit 1
	}
done

# A slot is test|package|checks|timeout; a test's weight is how often it is listed.
PLAN=()
add() {
	local n=$1 i
	shift
	for ((i = 0; i < n; i++)); do PLAN+=("$*"); done
}
tests() { grep -hoE '^func (Test[A-Za-z0-9_]+)' "$@" 2>/dev/null | sed 's/func //' | sort -u; }

add 4 "TestDeliveryConvergesThroughTheClient|mapper|1000|90m"
for t in $(tests hscontrol/mapper/route_property_test.go) TestSessionsFollowGeneratedScenarios TestHubSessionsConvergeUnderDrawnSchedules; do
	add 3 "$t|mapper|2000|90m"
done
for t in $(tests hscontrol/policy/v2/*_property_test.go hscontrol/policy/v2/*reference_test.go); do
	add 2 "$t|v2|5000|90m"
done
for t in $(tests hscontrol/state/world_property_test.go); do
	add 2 "$t|state|5000|90m"
done
# These seed themselves from the clock: every run is a fresh seed.
add 3 "TestSidesRandomDifferential|v2|-|60m"
add 3 "TestFiltersChangedCoversEveryMovedFilter|v2|-|60m"
add 3 "TestHubSessionsConvergeUnderConcurrency|mapper|-|60m"

printf '%s\n' "${PLAN[@]}" | sort -u >"$OUT/plan.txt"
echo "plan: $(wc -l <"$OUT/plan.txt") tests, $WORKERS workers, until $(date -d "@$END" '+%F %H:%M'), results in $OUT"

worker() {
	local w=$1 slot t k checks to seed log start rc secs f args
	while [ "$(date +%s)" -lt "$END" ] && [ ! -e "$OUT/STOP" ]; do
		slot=${PLAN[RANDOM % ${#PLAN[@]}]}
		IFS='|' read -r t k checks to <<<"$slot"
		seed=$(((RANDOM << 45) ^ (RANDOM << 30) ^ (RANDOM << 15) ^ RANDOM))
		log=$RUN/w$w.log
		start=$(date +%s)
		args=()
		if [ "$checks" != "-" ]; then
			args=(-rapid.checks="$checks" -rapid.seed="$seed" -rapid.nofailfile)
		else
			seed=clock
		fi
		(cd "$WT/${PKG[$k]}" && "$BIN/$k.test" -test.run "^${t}\$" -test.count=1 -test.timeout="$to" "${args[@]}" >"$log" 2>&1)
		rc=$?
		secs=$(($(date +%s) - start))
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -Is)" "$k" "$t" "$checks" "$seed" "$rc" "$secs" >>"$OUT/results.tsv"
		if [ "$rc" != 0 ]; then
			f="$OUT/fails/$(date +%m%d-%H%M%S)-$k-$t-$seed.log"
			# The head holds the verdict, the seed and the drawn case; logs can be huge.
			{
				grep -av '^{' "$log" | head -400
				echo "…"
				tail -60 "$log"
			} >"$f"
			echo "$(date -Is) FAIL $k $t checks=$checks seed=$seed -> $f" >>"$OUT/fails.log"
		fi
	done
}

for ((w = 1; w <= WORKERS; w++)); do worker "$w" & done
wait
echo "soak ended $(date -Is): $(wc -l <"$OUT/results.tsv") runs, $(awk -F'\t' '$6!=0' "$OUT/results.tsv" | wc -l) failed" | tee -a "$OUT/fails.log"
