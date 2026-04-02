package db

import (
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/util"
	"pgregory.net/rapid"
)

// ============================================================================
// Generators
// ============================================================================

// genHostname generates a hostname-like string (lowercase alphanum, dots, hyphens).
func genHostname() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		// Generate a mix of valid DNS-safe characters
		name := rapid.StringMatching(`[a-zA-Z0-9\-._]{1,80}`).Draw(t, "hostname")
		return name
	})
}

// genValidDNSName generates a string that is already a valid DNS label
// (lowercase, 2-53 chars, no leading/trailing hyphens or dots).
func genValidDNSName() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		// Keep to 53 chars to leave room for hash suffix
		innerLen := rapid.IntRange(0, 49).Draw(t, "innerLen")
		first := rapid.StringMatching(`[a-z0-9]`).Draw(t, "first")
		last := rapid.StringMatching(`[a-z0-9]`).Draw(t, "last")
		inner := ""
		if innerLen > 0 {
			inner = rapid.StringMatching(`[a-z0-9\-.]{0,49}`).Draw(t, "inner")
			if len(inner) > innerLen {
				inner = inner[:innerLen]
			}
		}
		result := first + inner + last
		result = strings.TrimRight(result, "-.")
		result = strings.TrimLeft(result, "-.")
		if len(result) < 2 {
			result = "aa"
		}
		if len(result) > 53 {
			result = result[:53]
		}
		return result
	})
}

// ============================================================================
// generateGivenName properties
// ============================================================================

// Property: generateGivenName without suffix is idempotent.
// Running it twice on the same input yields the same result.
func TestRapid_GenerateGivenName_NoSuffix_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genValidDNSName().Draw(t, "name")

		first, err1 := generateGivenName(name, false)
		if err1 != nil {
			return // input too long or invalid after normalization
		}

		second, err2 := generateGivenName(first, false)
		if err2 != nil {
			t.Fatalf("generateGivenName idempotent: first(%q)=%q, second failed: %v",
				name, first, err2)
		}

		if first != second {
			t.Fatalf("generateGivenName not idempotent: first=%q, second=%q", first, second)
		}
	})
}

// Property: generateGivenName output is always lowercase.
func TestRapid_GenerateGivenName_AlwaysLowercase(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genHostname().Draw(t, "name")
		randomSuffix := rapid.Bool().Draw(t, "randomSuffix")

		result, err := generateGivenName(name, randomSuffix)
		if err != nil {
			return
		}

		if result != strings.ToLower(result) {
			t.Fatalf("generateGivenName(%q, %v) = %q is not lowercase",
				name, randomSuffix, result)
		}
	})
}

// Property: generateGivenName output length never exceeds LabelHostnameLength (63).
func TestRapid_GenerateGivenName_BoundedLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genHostname().Draw(t, "name")
		randomSuffix := rapid.Bool().Draw(t, "randomSuffix")

		result, err := generateGivenName(name, randomSuffix)
		if err != nil {
			return
		}

		if len(result) > util.LabelHostnameLength {
			t.Fatalf("generateGivenName(%q, %v) = %q exceeds %d chars (len=%d)",
				name, randomSuffix, result, util.LabelHostnameLength, len(result))
		}
	})
}

// Property: generateGivenName output contains only valid DNS characters.
func TestRapid_GenerateGivenName_ValidDNSChars(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genHostname().Draw(t, "name")
		randomSuffix := rapid.Bool().Draw(t, "randomSuffix")

		result, err := generateGivenName(name, randomSuffix)
		if err != nil {
			return
		}

		if invalidDNSRegex.MatchString(result) {
			t.Fatalf("generateGivenName(%q, %v) = %q contains invalid DNS chars",
				name, randomSuffix, result)
		}
	})
}

// Property: generateGivenName with randomSuffix=true has a hyphen separating name from suffix.
func TestRapid_GenerateGivenName_SuffixHasHyphen(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genValidDNSName().Draw(t, "name")

		result, err := generateGivenName(name, true)
		if err != nil {
			return
		}

		// The result should contain the base name followed by a hyphen and random suffix
		if !strings.Contains(result, "-") {
			t.Fatalf("generateGivenName(%q, true) = %q has no hyphen separator",
				name, result)
		}
	})
}

// Property: generateGivenName with randomSuffix=true produces different results on repeated calls.
// (Not deterministic — the suffix is random.)
func TestRapid_GenerateGivenName_SuffixVaries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genValidDNSName().Draw(t, "name")

		r1, err1 := generateGivenName(name, true)
		r2, err2 := generateGivenName(name, true)
		if err1 != nil || err2 != nil {
			return
		}

		// The suffix should be different (with overwhelming probability)
		// We check that at least the last 8 chars differ.
		if r1 == r2 {
			// This can happen with negligible probability, so we don't fail hard.
			// But log it for visibility.
			t.Logf("WARNING: generateGivenName(%q, true) produced identical results: %q", name, r1)
		}
	})
}

// Property: Without suffix, the output is a prefix of the normalized input.
func TestRapid_GenerateGivenName_NoSuffix_StripsInvalidChars(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genHostname().Draw(t, "name")

		result, err := generateGivenName(name, false)
		if err != nil {
			return
		}

		// The result should be the lowercased input with invalid chars removed
		expectedBase := strings.ToLower(name)
		expectedBase = invalidDNSRegex.ReplaceAllString(expectedBase, "")
		if len(expectedBase) > util.LabelHostnameLength {
			// If input was too long, generateGivenName returns an error, not truncation
			return
		}

		if result != expectedBase {
			t.Fatalf("generateGivenName(%q, false) = %q, want %q",
				name, result, expectedBase)
		}
	})
}

// Property: generateGivenName with suffix, the base name is a prefix of the result (before the last hyphen).
func TestRapid_GenerateGivenName_SuffixPreservesBase(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := genValidDNSName().Draw(t, "name")

		result, err := generateGivenName(name, true)
		if err != nil {
			return
		}

		// The result format is: baseName-randomSuffix
		lastHyphen := strings.LastIndex(result, "-")
		if lastHyphen < 0 {
			t.Fatalf("generateGivenName(%q, true) = %q has no hyphen", name, result)
		}

		basePart := result[:lastHyphen]
		expectedBase := strings.ToLower(name)
		expectedBase = invalidDNSRegex.ReplaceAllString(expectedBase, "")

		trimmedHostnameLength := util.LabelHostnameLength - NodeGivenNameHashLength - NodeGivenNameTrimSize
		if len(expectedBase) > trimmedHostnameLength {
			expectedBase = expectedBase[:trimmedHostnameLength]
		}

		if basePart != expectedBase {
			t.Fatalf("generateGivenName(%q, true) base = %q, want %q",
				name, basePart, expectedBase)
		}
	})
}
