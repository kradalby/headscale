package v2

import (
	"maps"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
)

// formFloors are the least, at 100 checks, the capability-form property
// must judge of the form: filters holding a cap: source and filters the
// reference required one in, and filters by why their receiver must be
// sent addresses. Each sits at least five standard deviations below what
// default runs measure, so that no random seed misses one; the reasons too
// rare for that are floored per drawn scenario by TestCapFormCoverage.
var formFloors = map[string]int{
	"with a cap: source": 70, "required": 25,
	"receivers: eligible": 275, "receivers: routes": 180, "receivers: client": 35,
}

// formShareFloor is the least share of the filters judged of the form
// that hold a cap: source, on the same terms.
const formShareFloor = 0.08

// requireForm fails a capability-form run that judged less of the form
// than formFloors.
func requireForm(t *testing.T, form policymodel.FormJudge) {
	t.Helper()

	checks := rapidChecks()
	if checks < 100 {
		return
	}

	got := map[string]int{"with a cap: source": form.WithCaps, "required": form.Required}

	filters := 0

	for why, n := range form.Filters {
		filters += n

		if why == "" {
			why = "eligible"
		}

		got["receivers: "+why] = n
	}

	for kind, n := range form.ByRule {
		got["rules: "+kind] = n
	}

	for _, k := range slices.Sorted(maps.Keys(formFloors)) {
		if want := formFloors[k] * checks / 100; got[k] < want {
			t.Errorf("capability form: %d judged %s, want at least %d", got[k], k, want)
		}
	}

	if share := float64(form.WithCaps) / float64(max(1, filters)); share < formShareFloor {
		t.Errorf("capability form: %.2f of the filters judged hold a cap: source, want at least %.2f", share, formShareFloor)
	}
}
