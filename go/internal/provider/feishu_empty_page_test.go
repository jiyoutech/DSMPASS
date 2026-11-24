package provider

import (
	"github.com/dsmpass/dsmpass/go/internal/config"
	"net/http"
	"testing"
)

func TestFeishuEmptyTerminalPages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  map[string]any
		code  any
		valid bool
	}{
		{"missing", map[string]any{"has_more": false}, 0, true},
		{"explicit empty cursor", map[string]any{"has_more": false, "page_token": ""}, 0, true},
		{"array", map[string]any{"has_more": false, "items": []any{}}, 0, true},
		{"null list", map[string]any{"has_more": false, "items": nil}, 0, false},
		{"nonterminal", map[string]any{"has_more": true, "page_token": "more"}, 0, false},
		{"unexpected cursor", map[string]any{"has_more": false, "page_token": "more"}, 0, false},
		{"invalid cursor", map[string]any{"has_more": false, "page_token": nil}, 0, false},
		{"absent data", nil, 0, false},
		{"absent success code", map[string]any{"has_more": false}, nil, false},
		{"upstream error", map[string]any{"has_more": false}, 1, false},
	} {
		for _, kind := range []string{"users", "departments"} {
			for _, later := range []bool{false, true} {
				t.Run(kind+"/"+tc.name, func(t *testing.T) {
					f := NewFeishu(config.BackendConfig{FeishuContactBaseURL: "https://test.invalid"})
					f.client.Transport = fakeTransport(func(r *http.Request) (any, int) {
						if later && r.URL.Query().Get("page_token") == "" {
							return map[string]any{"code": 0, "data": map[string]any{"items": []any{map[string]any{"open_id": "u", "open_department_id": "d"}}, "has_more": true, "page_token": "next"}}, 200
						}
						response := map[string]any{"data": tc.data}
						if tc.code != nil {
							response["code"] = tc.code
						}
						return response, 200
					})
					read := f.departmentUsers
					if kind == "departments" {
						read = f.departmentChildren
					}
					rows, err := read("test", "leaf")
					want := 0
					if tc.valid && later {
						want = 1
					}
					if (err == nil) != tc.valid || len(rows) != want {
						t.Fatalf("later=%v rows=%v err=%v", later, rows, err)
					}
				})
			}
		}
	}
}
