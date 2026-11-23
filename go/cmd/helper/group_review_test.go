package main

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestReviewLocalGroups(t *testing.T) {
	groups := map[string]int{"财务": 65537, "design": 65605}
	for _, tc := range []struct {
		answer string
		want   map[string]int
	}{
		{"all\n", groups},
		{"2 1 2\n", groups},
		{"1 1\n", map[string]int{"design": 65605}},
		{"1 3\n2\n", map[string]int{"财务": 65537}},
		{"-1\nnone\n", map[string]int{}},
		{"none\n", map[string]int{}},
		{"0\n\n", nil},
		{"\n", nil},
		{"all", nil},
		{"", nil},
	} {
		t.Run(tc.answer, func(t *testing.T) {
			var out bytes.Buffer
			got, err := reviewLocalGroups(strings.NewReader(tc.answer), &out, groups)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			if !strings.Contains(out.String(), "1. \"design\" (GID 65605)\n2. \"财务\" (GID 65537)") {
				t.Fatal("scope not shown in stable order with GIDs")
			}
		})
	}
	got, err := reviewLocalGroups(strings.NewReader(""), io.Discard, nil)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty scope: %v, %v", got, err)
	}
	reader, writer := io.Pipe()
	reader.Close()
	defer writer.Close()
	if got, err := reviewLocalGroups(strings.NewReader("all\n"), writer, groups); err == nil || got != nil {
		t.Fatalf("approved without displaying scope: %v, %v", got, err)
	}
}
