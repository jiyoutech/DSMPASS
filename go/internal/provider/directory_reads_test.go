package provider

import (
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectoryReadWindowAndOrder(t *testing.T) {
	var active atomic.Int32
	var peak atomic.Int32
	release := make(chan struct{})
	ready := make(chan struct{})
	values := []int{7, 2, 2, 4, 5, 1, 6, 0, 8}
	go func() {
		select {
		case <-ready:
		case <-time.After(time.Second):
		}
		close(release)
	}()
	got, err := readDirectoryItems(values, func(i int) (int, error) {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		if n == directoryReadConcurrency {
			select {
			case <-ready:
			default:
				close(ready)
			}
		}
		<-release
		defer active.Add(-1)
		return i, nil
	})
	if err != nil || !slices.Equal(values, got) || peak.Load() != directoryReadConcurrency {
		t.Fatalf("values=%v concurrent=%d err=%v", got, peak.Load(), err)
	}
	if got, err := readDirectoryItems([]int{}, func(i int) (int, error) { t.Fatal("unexpected read"); return i, nil }); err != nil || len(got) != 0 {
		t.Fatalf("empty %v %v", got, err)
	}
}

func TestDirectoryReadFailureAndRetryAfter(t *testing.T) {
	for _, scenario := range []string{"retry", "repeat", "denied", "long_wait"} {
		t.Run(scenario, func(t *testing.T) {
			items := []int{0, 1, 2, 3, 4, 5}
			counts := make([]int, len(items))
			var mu sync.Mutex
			got, err := readDirectoryItems(items, func(id int) (int, error) {
				mu.Lock()
				counts[id]++
				attempt := counts[id]
				mu.Unlock()
				if id == 1 {
					resp := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"0"}}}
					switch scenario {
					case "denied":
						resp.StatusCode = 403
					case "long_wait":
						resp.Header.Set("Retry-After", "31")
					}
					if attempt == 1 || scenario == "repeat" {
						return 0, directoryHTTPError(resp, errors.New("directory error"))
					}
				}
				return id, nil
			})
			if scenario == "retry" {
				if err != nil || !slices.Equal(got, items) || !slices.Equal(counts, []int{1, 2, 1, 1, 1, 1}) {
					t.Fatalf("%v %v %v", got, counts, err)
				}
			} else if err == nil || got != nil || counts[4] != 0 || counts[5] != 0 {
				t.Fatalf("partial results or reads after failed window: %v %v %v", got, counts, err)
			}
		})
	}
}

func TestDirectoryPageRetriesTransientErrorWithoutDuplicatingRows(t *testing.T) {
	calls := 0
	page, err := readDirectoryPage(func() (map[string]any, error) {
		calls++
		if calls == 1 {
			return map[string]any{"partial": true}, directoryHTTPError(&http.Response{StatusCode: 503}, errors.New("busy"))
		}
		return map[string]any{"items": []any{}}, nil
	})
	if err != nil || calls != 2 || page["partial"] != nil {
		t.Fatal(page, calls, err)
	}
	for _, tc := range []struct {
		name string
		data map[string]any
		ok   bool
	}{
		{"short terminal", map[string]any{}, true},
		{"full terminal", map[string]any{"has_more": false}, true},
		{"legacy terminal", map[string]any{}, true},
		{"orphan cursor", map[string]any{"page_token": "2"}, false},
		{"malformed flag", map[string]any{"has_more": "false"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := directoryPageHasMore(tc.data, "page_token"); (err == nil) != tc.ok {
				t.Fatal(err)
			}
		})
	}
	if _, err := directoryPageItems(map[string]any{"items": []any{map[string]any{}, "bad"}}, "items"); err == nil {
		t.Fatal("malformed row accepted")
	}
}
