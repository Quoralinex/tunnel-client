package clientcapabilities

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Shared protocol cases let independently implemented consumers agree on the
// complete advertisement, including unknown names and malformed suffixes.
//
//go:embed testdata/parse_cases.json
var parseCasesJSON []byte

func TestParseSharedCases(t *testing.T) {
	t.Parallel()
	var cases []struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
		Want   []string `json:"want"`
	}
	if err := json.Unmarshal(parseCasesJSON, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("missing protocol cases")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			got := Parse(tc.Values)
			names := make([]string, 0, len(got.names))
			for name := range got.names {
				names = append(names, name)
			}
			slices.Sort(names)
			if !slices.Equal(names, tc.Want) {
				t.Fatalf("parsed %q, want %q", names, tc.Want)
			}
			if got.Supports(WrongClusterV1) != slices.Contains(tc.Want, WrongClusterV1) {
				t.Fatal("routing correction capability must require exact membership")
			}
			if got.Supports("") || got.Supports("wrong-cluster") {
				t.Fatal("empty or prefix names are not capabilities")
			}
		})
	}
}

func TestParseBoundsEmptyRepeatedFields(t *testing.T) {
	t.Parallel()
	values := make([]string, MaxValueBytes+2)
	values[0] = WrongClusterV1
	if got := Parse(values); len(got.names) != 0 {
		t.Fatal("separators count toward the aggregate value limit")
	}
}

func TestFormatCanonicalSet(t *testing.T) {
	t.Parallel()
	names := []string{WrongClusterV1, "z-future", "a-future", WrongClusterV1}
	original := slices.Clone(names)
	got, err := Format(names...)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a-future,wrong-cluster-v1,z-future"; got != want {
		t.Fatalf("formatted %q, want %q", got, want)
	}
	if !slices.Equal(names, original) {
		t.Fatal("formatting must not mutate the caller's capability list")
	}
	parsed := Parse([]string{got})
	for _, name := range names {
		if !parsed.Supports(name) {
			t.Errorf("canonical advertisement lost %q", name)
		}
	}
	if got, err := Format(); err != nil || got != "" {
		t.Fatalf("empty advertisement = %q, %v", got, err)
	}
}

func TestFormatRejectsInvalidNamesAndBounds(t *testing.T) {
	t.Parallel()
	tooMany := make([]string, MaxMembers+1)
	for i := range tooMany {
		tooMany[i] = WrongClusterV1
	}
	tooLong := make([]string, 32)
	for i := range tooLong {
		tooLong[i] = fmt.Sprintf("%03d%s", i, strings.Repeat("x", MaxTokenBytes-3))
	}
	for _, names := range [][]string{
		{""}, {"a,b"}, {"wrong-cluster-v1 "}, {"wrong-cluster-v1\t"},
		{"bad=name"}, {"é"}, {strings.Repeat("x", MaxTokenBytes+1)},
		tooMany, tooLong,
	} {
		if value, err := Format(names...); err == nil || value != "" {
			t.Errorf("invalid names emitted an advertisement: %q, %v", value, err)
		}
	}
}

func TestAdvertisedContainsOnlyImplementedCapabilities(t *testing.T) {
	t.Parallel()
	want, err := Format(WrongClusterV1)
	if err != nil {
		t.Fatal(err)
	}
	if got := Advertised(); got != want {
		t.Fatalf("advertised %q, want implemented set %q", got, want)
	}
}
