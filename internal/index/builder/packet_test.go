package builder

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestReadPacketsMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "input.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	first := time.Unix(100, 0)
	for i, timestamp := range []time.Time{first.Add(time.Second), first} {
		data := []byte{byte(i), 1, 2, 3}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	info, packets, storage, err := readPackets(dir, "input.pcap", nil, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if packets != nil || storage != nil || info.PacketCount != 2 || !info.PacketTimestampMin.Equal(first) || !info.PacketTimestampMax.Equal(first.Add(time.Second)) {
		t.Fatalf("metadata-only scan: info=%+v, packets=%v", info, packets)
	}
	budget := int64(5)
	_, packets, storage, err = readPackets(dir, "input.pcap", info, false, &budget)
	if err != nil {
		t.Fatal(err)
	}
	if storage == nil || len(packets) != 2 || packets[0].data != nil || packets[1].data != nil {
		t.Fatalf("full read returned unexpected packets: %v", packets)
	}
	if budget != 5 {
		t.Fatalf("remaining packet payload budget = %d, want 5 after spilling", budget)
	}
	for i := range packets {
		parsed, err := packets[i].Parsed(storage)
		if err != nil || parsed.Data()[0] != byte(i) {
			t.Fatalf("spooled packet %d: data=%v, err=%v", i, parsed, err)
		}
	}
	name := storage.file.Name()
	storage.Close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("temporary packet data still exists: %v", err)
	}
}
