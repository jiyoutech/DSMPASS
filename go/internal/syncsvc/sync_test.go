package syncsvc

import (
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/provider"
)

func TestDisambiguateDuplicateGroupNamesUsesPathOnlyForDuplicates(t *testing.T) {
	groups := []provider.Group{
		{Subject: "sup5-a", Name: "sup5", Path: "matrix/sup1/sup2/sup5"},
		{Subject: "sup5-b", Name: "sup5", Path: "matrix/sup1/sup3/sup5"},
		{Subject: "marketing", Name: "marketing", Path: "matrix/marketing"},
	}
	got := disambiguateDuplicateGroupNames(groups)

	if got[0].Name != "matrix/sup1/sup2/sup5" {
		t.Fatalf("first duplicate name got %q", got[0].Name)
	}
	if got[1].Name != "matrix/sup1/sup3/sup5" {
		t.Fatalf("second duplicate name got %q", got[1].Name)
	}
	if got[2].Name != "marketing" {
		t.Fatalf("unique name should stay unchanged, got %q", got[2].Name)
	}
	if groups[0].Name != "sup5" {
		t.Fatalf("input groups should not be mutated")
	}
}
