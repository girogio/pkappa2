package attackflags

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
		{"SaarCTF attack JSON", `{"teams":[{"id":1,"ip":"10.42.1.2"}],"flag_ids":{"fooserv":{"10.42.1.2":{"123":["info_flag1","info_flag2"]}},"barserv":{"10.42.1.2":{"123":"info_single"}}}}`, "flag_ids", []string{"info_flag1", "info_flag2", "info_single"}},
		{"ECSC 2026 attack JSON with default path", `{"teams":[{"id":2,"ip":"10.60.2.2"}],"attack_info":{"fireworx":{"10.60.2.2":{"83":{"0":"first-id"},"84":{"0":null}}},"bambinotes":{"10.60.2.2":{"83":{"0":"second-id"}}}},"current_round":84}`, "flag_ids", []string{"first-id", "second-id"}},
		{"ECSC 2026 attack JSON with explicit path", `{"attack_info":{"fireworx":{"10.60.2.2":{"83":{"0":"first-id"}}}}}`, "attack_info", []string{"first-id"}},
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

func TestMatcherReusesSnapshotsAndReportsChangedTime(t *testing.T) {
	stateDir := t.TempDir()
	config := Config{URL: "http://example.invalid/attack.json", Path: "flag_ids", TickDuration: 10 * time.Second, StateDir: stateDir}
	first := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	records := []snapshot{
		{At: first, IDs: []string{"old-id"}},
		{At: first.Add(10 * time.Second), IDs: []string{"new-id"}},
	}
	var archive []byte
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		archive = append(append(archive, line...), '\n')
	}
	if err := os.WriteFile(archiveFilename(stateDir, config.URL, config.Path), archive, 0600); err != nil {
		t.Fatal(err)
	}
	feed, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if at, ok := feed.ChangedSince(1); !ok || !at.Equal(records[1].At) {
		t.Fatalf("ChangedSince(1) = %v, %v", at, ok)
	}
	data := []index.Data{
		{Time: first.Add(-time.Minute), Content: []byte("old-id")},
		{Time: first.Add(7 * time.Second), Content: []byte("new-id")},
		{Time: first.Add(11 * time.Second), Content: []byte("new-id")},
		{Time: first.Add(11 * time.Second), Content: []byte("no match")},
	}
	matcher, err := feed.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer matcher.Close()
	got, err := matcher.Match(data)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"old-id"}, {"new-id"}, {"new-id"}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matcher.Match = %q, want %q", got, want)
	}
	for i, chunk := range data {
		found, err := matcher.HasMatch([]index.Data{chunk})
		if err != nil || found != (len(want[i]) != 0) {
			t.Fatalf("Matcher.HasMatch(chunk %d) = %v, %v", i, found, err)
		}
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
	beforeFirstFetch := time.Now().Add(-time.Minute)
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
		{Time: beforeFirstFetch, Content: []byte("packet old-flag-id from before setup")},
		{Time: oldTime, Content: []byte("packet old-flag-id here")},
		{Time: oldTime, Content: []byte("packet with no matching ID")},
		{Time: newTime, Content: []byte("packet new-flag-id here")},
	}
	got, err := f.Match(chunks)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"old-flag-id"}, {"old-flag-id"}, {}, {"new-flag-id"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `[["old-flag-id"],["old-flag-id"],[],["new-flag-id"]]` {
		t.Fatalf("Match() JSON contains a null chunk: %s", encoded)
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
