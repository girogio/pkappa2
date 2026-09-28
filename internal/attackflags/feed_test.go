package attackflags

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/spq/pkappa2/internal/index"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name, body, path string
		want             []string
	}{
		{"flat", `{"flag_ids":["b","a","b"]}`, "flag_ids", []string{"a", "b"}},
		{"nested", `{"services":[{"flags":{"ids":["red"]}},{"flags":{"ids":["blue"]}}]}`, "services.*.flags.ids", []string{"blue", "red"}},
		{"map and numbers", `{"flag_ids":{"team_a":["abc",42],"team_b":null}}`, "flag_ids", []string{"42", "abc"}},
		{"array index", `{"ticks":[{"ids":["old"]},{"ids":["new"]}]}`, "ticks.1.ids", []string{"new"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Extract([]byte(tc.body), tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Extract() = %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := Extract([]byte(`{"other":[]}`), "flag_ids"); err == nil {
		t.Fatal("missing path should fail so the last valid snapshot is retained")
	}
	if _, err := Extract([]byte(`{"flag_ids":[true]}`), "flag_ids"); err == nil {
		t.Fatal("unexpected ID type should fail")
	}
}

func TestFeedRotatesAndRestoresHistoricalIDs(t *testing.T) {
	var mu sync.Mutex
	body := `{"flags":{"ids":["old-flag-id"]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	config := Config{URL: server.URL, Path: "flags.ids", TickDuration: 10 * time.Second, StateDir: t.TempDir()}
	f, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now()
	if f.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", f.Generation())
	}
	if err := f.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.Generation() != 1 {
		t.Fatal("unchanged feed should not append a snapshot")
	}
	mu.Lock()
	body = `{"flags":{"ids":["new-flag-id"]}}`
	mu.Unlock()
	if err := f.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	newTime := time.Now()
	chunks := []index.Data{
		{Time: oldTime, Content: []byte("packet old-flag-id here")},
		{Time: newTime, Content: []byte("packet new-flag-id here")},
	}
	got, err := f.Match(chunks)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"old-flag-id"}, {"new-flag-id"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %q, want %q", got, want)
	}
	restored, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err = restored.Match(chunks)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("restored Match() = %q, %v; want %q", got, err, want)
	}
	mu.Lock()
	body = `{"invalid":true}`
	mu.Unlock()
	if err := f.Fetch(context.Background()); err == nil {
		t.Fatal("invalid response should fail")
	}
	if f.Generation() != 2 {
		t.Fatal("invalid response replaced the last valid snapshot")
	}
}
