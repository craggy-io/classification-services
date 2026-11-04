package signatures_test

import (
	"testing"

	"github.com/craggy-io/classification-services/signatures"
)

func TestNewRejectsDegeneratePatterns(t *testing.T) {
	for _, r := range []signatures.Rule{
		{ID: "empty", Type: "x.y", Patterns: []signatures.Pattern{{Offset: 0}}},
		{ID: "neg", Type: "x.y", Patterns: []signatures.Pattern{signatures.Literal(-2, []byte("AB"))}},
		{ID: "emptybytes", Type: "x.y", Patterns: []signatures.Pattern{signatures.Literal(0, nil)}},
		{ID: "emptyset", Type: "x.y", Patterns: []signatures.Pattern{{Offset: 0, Sets: []signatures.ByteSet{{}}}}},
	} {
		if _, err := signatures.New([]signatures.Rule{r}); err == nil {
			t.Errorf("rule %s accepted", r.ID)
		}
	}
}

func TestMatcherIsImmutable(t *testing.T) {
	sets := []signatures.ByteSet{signatures.Only('A')}
	m, err := signatures.New([]signatures.Rule{{ID: "r", Type: "x.y", Patterns: []signatures.Pattern{{Offset: 0, Sets: sets}}}})
	if err != nil {
		t.Fatal(err)
	}
	sets[0] = signatures.Only('B') // mutate the caller's slice after New
	if hits := m.Match([]byte("A"), 1); len(hits) != 1 {
		t.Fatalf("caller mutation changed matcher: %v", hits)
	}
	rules := m.Rules()
	rules[0].Patterns[0].Sets[0] = signatures.Only('B') // mutate the returned copy
	if hits := m.Match([]byte("A"), 1); len(hits) != 1 {
		t.Fatalf("Rules() mutation changed matcher: %v", hits)
	}
}

func TestCyberChefEmptyOneOfRejected(t *testing.T) {
	data := []byte(`{"version":1,"rules":[{"id":"x","type":"a.b","alternatives":[[{"offset":0,"op":"one_of","values":[]}]]}]}`)
	if _, _, err := signatures.ParseCyberChef(data, "test"); err == nil {
		t.Fatal("empty one_of accepted")
	}
}
