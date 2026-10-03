package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spq/pkappa2/internal/attackflags"
	"github.com/spq/pkappa2/internal/index/manager"
)

type flagIDTestPacket struct {
	port    layers.UDPPort
	at      time.Time
	content string
}

func importFlagIDTestPackets(t *testing.T, mgr *manager.Manager, pcapDir, name string, packets []flagIDTestPacket) []uint64 {
	t.Helper()
	file, err := os.Create(filepath.Join(pcapDir, name))
	if err != nil {
		t.Fatal(err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeIPv4)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range packets {
		ip := layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{1, 2, 3, 4}, DstIP: []byte{5, 6, 7, 8}, Protocol: layers.IPProtocolUDP}
		udp := layers.UDP{SrcPort: packet.port, DstPort: 4321}
		if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
			t.Fatal(err)
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, &ip, &udp, gopacket.Payload(packet.content)); err != nil {
			t.Fatal(err)
		}
		payload := buffer.Bytes()
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: packet.at, CaptureLength: len(payload), Length: len(payload)}, payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	events, stop := mgr.Listen()
	defer stop()
	mgr.ImportPcaps([]string{name})
	deadline := time.After(5 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Type == "pcapProcessed" {
				return event.ChangedStreamIDs
			}
		case <-deadline:
			t.Fatal("timed out waiting for pcapProcessed")
		}
	}
}

func TestFlagIDTagIncrementalRefresh(t *testing.T) {
	dirs := makeTempdirs(t)
	mgr := makeManager(t, dirs)
	defer mgr.Close()
	var mu sync.Mutex
	body := `{"flag_ids":["old-id"]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	feed, err := attackflags.New(attackflags.Config{URL: server.URL, Path: "flag_ids", TickDuration: 2 * time.Minute, StateDir: dirs.state})
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	changed := importFlagIDTestPackets(t, mgr, dirs.pcap, "initial.pcapng", []flagIDTestPacket{
		{port: 1001, at: now.Add(-3 * time.Minute), content: "old-id"},
		{port: 1002, at: now, content: "new-id"},
	})
	if len(changed) != 2 {
		t.Fatalf("initial changed streams = %v", changed)
	}
	matches, retry, err := syncFlagIDTag(context.Background(), mgr, feed, nil, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry) != 0 {
		t.Fatalf("unexpected unreadable streams: %v", retry)
	}
	if len(matches) != 1 || mgr.ListTags()[0].MatchingCount != 1 {
		t.Fatalf("initial matches = %v", matches)
	}
	mu.Lock()
	body = `{"flag_ids":["new-id"]}`
	mu.Unlock()
	if err := feed.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	at, ok := feed.ChangedSince(1)
	if !ok {
		t.Fatal("missing changed snapshot")
	}
	cutoff := at.Add(-feed.PollInterval())
	matches, retry, err = syncFlagIDTag(context.Background(), mgr, feed, matches, false, &cutoff, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry) != 0 {
		t.Fatalf("unexpected unreadable streams: %v", retry)
	}
	if len(matches) != 2 || mgr.ListTags()[0].MatchingCount != 2 {
		t.Fatalf("matches after feed change = %v", matches)
	}
	changed = importFlagIDTestPackets(t, mgr, dirs.pcap, "later.pcapng", []flagIDTestPacket{
		{port: 1003, at: time.Now(), content: "new-id"},
	})
	dirty := make(map[uint64]struct{})
	for _, id := range changed {
		dirty[id] = struct{}{}
	}
	matches, retry, err = syncFlagIDTag(context.Background(), mgr, feed, matches, false, nil, dirty)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry) != 0 {
		t.Fatalf("unexpected unreadable streams: %v", retry)
	}
	if len(matches) != 3 || mgr.ListTags()[0].MatchingCount != 3 {
		t.Fatalf("matches after import = %v", matches)
	}
}
