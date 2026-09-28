package attackflags

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestControllerSettingsPersistAndReconfigure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"flag_ids":["flag-id"]}`))
	}))
	defer server.Close()
	stateDir := t.TempDir()
	c, err := NewController(stateDir, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if feed, _, _ := c.Current(); feed != nil {
		t.Fatal("feed should start disabled")
	}
	settings := Settings{URL: server.URL, Path: "flag_ids", TickDuration: "10s"}
	got, err := c.Update(settings)
	if err != nil || !reflect.DeepEqual(got, settings) {
		t.Fatalf("Update() = %+v, %v", got, err)
	}
	feed, version, _ := c.Current()
	if feed == nil {
		t.Fatal("feed was not started")
	}
	if _, err := c.Update(Settings{URL: "://bad", Path: "flag_ids", TickDuration: "10s"}); err == nil {
		t.Fatal("invalid URL should be rejected")
	}
	if c.Settings() != settings {
		t.Fatal("invalid update changed saved settings")
	}
	if current, _, _ := c.Current(); current == nil {
		t.Fatal("invalid update stopped the previous feed")
	}
	// Changing only the tick duration reloads the same archive after stopping
	// the previous poller, and also changes the version seen by an open view.
	settings.TickDuration = "20s"
	if _, err := c.Update(settings); err != nil {
		t.Fatal(err)
	}
	if _, nextVersion, _ := c.Current(); nextVersion == version {
		t.Fatal("configuration change did not advance the version")
	}
	c.Close()
	restored, err := NewController(stateDir, Settings{URL: "http://ignored.example", Path: "other", TickDuration: "2m"})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.Settings() != settings {
		t.Fatalf("restored settings = %+v, want %+v", restored.Settings(), settings)
	}
	settings.URL = ""
	if _, err := restored.Update(settings); err != nil {
		t.Fatal(err)
	}
	if current, _, _ := restored.Current(); current != nil {
		t.Fatal("clearing URL did not disable feed")
	}
}
