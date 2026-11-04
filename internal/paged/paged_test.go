package paged_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/craggy-io/classification-services/internal/paged"
)

func TestBudgetAndMemo(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 3*paged.PageSize)
	r := paged.New(bytes.NewReader(data), int64(len(data)), paged.PageSize)
	if b, err := r.ReadRange(0, 10); err != nil || len(b) != 10 {
		t.Fatal(err)
	}
	if _, err := r.ReadRange(paged.PageSize, 10); err != nil {
		t.Fatalf("second page within slack: %v", err)
	}
	if _, err := r.ReadRange(2*paged.PageSize, 10); !errors.Is(err, paged.ErrBudget) || !r.Exhausted() {
		t.Fatalf("over budget: %v", err)
	}
	if b, err := r.ReadRange(5, 3); err != nil || string(b) != "xxx" {
		t.Fatalf("cached page after exhaustion: %q %v", b, err)
	}
	j := paged.New(bytes.NewReader([]byte(`{"a":1} `)), 8, 0)
	v1, err1 := j.JSON(0)
	v2, _ := j.JSON(0)
	if err1 != nil || v1.(map[string]any)["a"] == nil || &v1 == nil || v2 == nil {
		t.Fatalf("json = %v %v", v1, err1)
	}
	if _, err := paged.New(bytes.NewReader([]byte(`{} {}`)), 5, 0).JSON(0); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := j.View("no-such-view"); err == nil {
		t.Fatal("unknown view accepted")
	}
}
