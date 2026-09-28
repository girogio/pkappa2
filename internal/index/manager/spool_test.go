package manager

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func TestPcapSpoolFlush(t *testing.T) {
	dir := t.TempDir()
	spool := pcapSpool{dir: dir}
	for _, packet := range []pcapOverIPPacket{
		{linkType: layers.LinkTypeEthernet, data: []byte{1}, ci: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: 1, Length: 1}},
		{linkType: layers.LinkTypeRaw, data: []byte{2}, ci: gopacket.CaptureInfo{Timestamp: time.Unix(2, 0), CaptureLength: 1, Length: 1}},
		{linkType: layers.LinkTypeEthernet, data: []byte{3}, ci: gopacket.CaptureInfo{Timestamp: time.Unix(3, 0), CaptureLength: 1, Length: 1}},
	} {
		if err := spool.add(packet); err != nil {
			t.Fatal(err)
		}
	}
	filenames, err := spool.flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(filenames) != 2 || len(spool.files) != 0 {
		t.Fatalf("flush returned %d files and kept %d open files", len(filenames), len(spool.files))
	}
	seen := map[byte]bool{}
	for _, name := range filenames {
		handle, err := pcap.OpenOffline(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for {
			data, _, err := handle.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			seen[data[0]] = true
		}
		handle.Close()
	}
	if len(seen) != 3 || !seen[1] || !seen[2] || !seen[3] {
		t.Fatalf("spooled packet contents: %v", seen)
	}
}
