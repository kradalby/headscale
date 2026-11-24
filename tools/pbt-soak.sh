#!/usr/bin/env bash
# Soaks the property tests: every property in rotation, fresh seeds, deep
# budgets, several workers, until the time is up or a file named STOP appears
# in the output directory. See hscontrol/policy/policymodel/README.md.
#
# usage: tools/pbt-soak.sh [worktree=.] [hours=8] [workers=6]
# PBT_SOAK_OUT (default <worktree>/pbt-soak) takes results.tsv, fails.log and
# the log of each failed run; PBT_SOAK_BIN takes the test binaries, built once.
# With PBT_SOAK_SMOKE=1 the hours and workers are ignored: every slot of the
# plan runs once, its checks capped (a plain slot at PBT_SOAK_SMOKE_CHECKS,
# default 30, a race slot at a tenth) and -test.short on, so the budget-
# sensitive coverage floors stay out of the way; it proves every deep
# invocation works in a bounded pass.
# The script exits non-zero once any run failed.
set -uo pipefail

WT=$(cd "${1:-.}" && pwd) || exit 1
HOURS=${2:-8}
WORKERS=${3:-6}
SMOKE=${PBT_SOAK_SMOKE:-0}
SMOKE_CHECKS=${PBT_SOAK_SMOKE_CHECKS:-30}
SMK_CAP=$SMOKE_CHECKS
OUT=${PBT_SOAK_OUT:-$WT/pbt-soak}
BIN=${PBT_SOAK_BIN:-${TMPDIR:-/tmp}/pbt-soak-bin}
RUN=$BIN/run
mkdir -p "$OUT/fails" "$BIN" "$RUN"
END=$(($(date +%s) + HOURS * 3600))

declare -A PKG=(
	[mapper]=hscontrol/mapper [v2]=hscontrol/policy/v2 [state]=hscontrol/state
	[model]=hscontrol/policy/policymodel [scope]=hscontrol/scope [types]=hscontrol/types
	[matcher]=hscontrol/policy/matcher [servertest]=hscontrol/servertest
	[graph]=hscontrol/graph
)
# Cases per run: by package, unless the test is named. Cheap properties get more.
declare -A DEPTH=([mapper]=2000 [v2]=5000 [state]=5000 [servertest]=1000)
declare -A CHECKS=(
	[TestDeliveryConvergesThroughTheClient]=1000
	[TestChunkDeltaConverges]=50000 [TestChunkEncodingRoundTrips]=50000
	[TestMatcherRouteRangesMatchPrefixes]=50000 [TestBuildPeerMapMatchesPrefixReference]=50000
)
# How often a test is listed: the session properties cost the most per case
# and reach the most code.
declare -A WEIGHT=([TestDeliveryConvergesThroughTheClient]=4 [TestSessionsFollowGeneratedScenarios]=3 [TestHubSessionsConvergeUnderDrawnSchedules]=3)
# -rapid.steps lengthens these; one run in three trades cases for length.
STEPPED=" TestDeliveryConvergesThroughTheClient TestHubSessionsConvergeUnderDrawnSchedules "
# Built with the race detector as well, a tenth of the cases.
RACED="mapper state servertest graph"

cd "$WT" || exit 1
git rev-parse HEAD >"$OUT/commit"
: >>"$OUT/results.tsv"

for k in "${!PKG[@]}"; do
	[ -x "$BIN/$k.test" ] || go test -c -o "$BIN/$k.test" "./${PKG[$k]}" || {
		echo "build failed: $k"
		exit 1
	}
done
for k in $RACED; do
	[ -x "$BIN/$k.race.test" ] || CGO_ENABLED=1 go test -race -c -o "$BIN/$k.race.test" "./${PKG[$k]}" || {
		echo "race build failed, no race runs: $k"
		RACED=${RACED/$k/}
	}
done

# A slot is test|package|checks|timeout|race.
PLAN=()
add() {
	local n=$1 i
	shift
	for ((i = 0; i < n; i++)); do PLAN+=("$*"); done
}
# Every test that calls rapid.Check itself, so a new property joins the soak
# without being listed here.
props() { awk '/^func /{f=$2; sub(/\(.*/,"",f)} /rapid\.Check\(/ && f ~ /^Test/ {print f}' "$1"/*_test.go | sort -u; }

for k in "${!PKG[@]}"; do
	# These two reach rapid through a helper.
	extra=
	[ "$k" = v2 ] && extra="TestProductionShapesReached TestReferenceAgreesWithCaptures"
	for t in $(props "${PKG[$k]}") $extra; do
		c=${CHECKS[$t]:-${DEPTH[$k]:-50000}}
		add "${WEIGHT[$t]:-2}" "$t|$k|$c|90m|"
		case " $RACED " in *" $k "*) add 1 "$t|$k|$((c / 10))|120m|race" ;; esac
	done
done
# These seed themselves from the clock: every run is a fresh seed.
add 3 "TestSidesRandomDifferential|v2|-|60m|"
add 3 "TestFiltersChangedCoversEveryMovedFilter|v2|-|60m|"
add 3 "TestHubSessionsConvergeUnderConcurrency|mapper|-|60m|"
add 1 "TestHubSessionsConvergeUnderConcurrency|mapper|-|60m|race"

printf '%s\n' "${PLAN[@]}" | sort -u >"$OUT/plan.txt"
echo "plan: $(wc -l <"$OUT/plan.txt") slots, ${SMOKE:+smoke,}$WORKERS workers, $( [ "$SMOKE" = 1 ] || echo "until $(date -d "@$END" '+%F %H:%M'), ")results in $OUT"

# run_slot runs one slot of the plan, appending its result. A smoke pass
# caps the checks, so a deep invocation is proven without its deep cost.
run_slot() {
	local slot=$1 w=$2 t k checks to race seed log start rc secs f args bin steps mode
	IFS='|' read -r t k checks to race <<<"$slot"
	seed=$(((RANDOM << 45) ^ (RANDOM << 30) ^ (RANDOM << 15) ^ RANDOM))
	log=$RUN/w$w.log
	start=$(date +%s)
	bin=$BIN/$k${race:+.race}.test
	mode=${race:--}
	args=()
	if [ "$checks" != "-" ]; then
		if [[ "$STEPPED" == *" $t "* ]] && ((RANDOM % 3 == 0)); then
			steps=$((60 + RANDOM % 240))
			checks=$((checks * 30 / steps + 1))
			args+=(-rapid.steps="$steps")
			mode=${race:+race,}steps=$steps
		fi
		if [ "$SMOKE" = 1 ]; then
			# A tenth for a race slot: the race build itself is what the
			# smoke proves, not a deep pass through it.
			local cap=$SMK_CAP
			[ "$race" = race ] && cap=$((SMK_CAP / 10))
			checks=$((checks < cap ? checks : cap))
		fi
		args+=(-rapid.checks="$checks" -rapid.seed="$seed" -rapid.nofailfile)
	else
		seed=clock
	fi
	[ "$SMOKE" = 1 ] && args+=(-test.short=true)
	(cd "$WT/${PKG[$k]}" && "$bin" -test.run "^${t}\$" -test.count=1 -test.timeout="$to" "${args[@]}" >"$log" 2>&1)
	rc=$?
	secs=$(($(date +%s) - start))
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -Is)" "$k" "$t" "$checks" "$seed" "$rc" "$secs" "$mode" >>"$OUT/results.tsv"
	if [ "$rc" != 0 ]; then
		f="$OUT/fails/$(date +%m%d-%H%M%S)-$k-$t-$seed.log"
		# The head holds the verdict, the seed and the drawn case; logs can be huge.
		{
			echo "ran: cd $WT/${PKG[$k]} && $bin -test.run '^${t}\$' -test.count=1 -test.timeout=$to ${args[*]}"
			grep -av '^{' "$log" | head -400
			echo "…"
			tail -60 "$log"
		} >"$f"
		echo "$(date -Is) FAIL $k $t checks=$checks seed=$seed mode=$mode -> $f" >>"$OUT/fails.log"
	fi
}

if [ "$SMOKE" = 1 ]; then
	echo "smoke: $(wc -l <"$OUT/plan.txt") slots, one run each, checks capped at $SMOKE_CHECKS"
	while IFS= read -r slot; do
		run_slot "$slot" smoke
	done <"$OUT/plan.txt"
else
	for ((w = 1; w <= WORKERS; w++)); do
		(
			while [ "$(date +%s)" -lt "$END" ] && [ ! -e "$OUT/STOP" ]; do
				run_slot "${PLAN[RANDOM % ${#PLAN[@]}]}" "$w"
			done
		) &
	done
	wait
fi

FAILED=$(awk -F'\t' '$6 != 0' "$OUT/results.tsv" | wc -l)
echo "soak ended $(date -Is): $(wc -l <"$OUT/results.tsv") runs, $FAILED failed" | tee -a "$OUT/fails.log"
[ "$FAILED" = 0 ] || exit 1
