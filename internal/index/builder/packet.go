package builder

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	pcapmetadata "github.com/spq/pkappa2/internal/tools/pcapMetadata"
)

type (
	Packet struct {
		p       gopacket.Packet
		ci      gopacket.CaptureInfo
		data    []byte
		decoder gopacket.Decoder
	}
	packetStorage struct {
		file      *os.File
		writer    *bufio.Writer
		size      int64
		locations []packetLocation
	}
	packetLocation struct {
		offset int64
		length int
	}
)

func (s *packetStorage) Write(data []byte) error {
	offset := s.size
	n, err := s.writer.Write(data)
	s.size += int64(n)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	s.locations = append(s.locations, packetLocation{offset, len(data)})
	return nil
}

func (s *packetStorage) Close() {
	name := s.file.Name()
	s.file.Close()
	os.Remove(name)
}

func (p *Packet) Parsed(storage *packetStorage) (gopacket.Packet, error) {
	if p.p == nil {
		if storage != nil && p.data == nil {
			pmd := pcapmetadata.FromPacketMetadata(&p.ci)
			if pmd == nil || pmd.Index >= uint64(len(storage.locations)) {
				return nil, fmt.Errorf("temporary packet data location missing")
			}
			location := storage.locations[pmd.Index]
			p.data = make([]byte, location.length)
			if _, err := storage.file.ReadAt(p.data, location.offset); err != nil {
				return nil, fmt.Errorf("reading temporary packet data: %w", err)
			}
		}
		p.p = gopacket.NewPacket(p.data, p.decoder, gopacket.NoCopy)
		md := p.p.Metadata()
		md.CaptureInfo = p.ci
		md.Truncated = md.Truncated || p.ci.CaptureLength < p.ci.Length
	}
	return p.p, nil
}

func (p *Packet) Timestamp() time.Time {
	return p.ci.Timestamp
}

func (p *Packet) CaptureInfo() *gopacket.CaptureInfo {
	return &p.ci
}

func readPackets(pcapDir, pcapFilename string, info *pcapmetadata.PcapInfo, metadataOnly bool, memoryBudget *int64) (*pcapmetadata.PcapInfo, []Packet, *packetStorage, error) {
	updateInfo := info == nil
	if updateInfo {
		info = &pcapmetadata.PcapInfo{
			Filename:  pcapFilename,
			ParseTime: time.Now(),
		}
		if s, err := os.Stat(filepath.Join(pcapDir, pcapFilename)); err != nil {
			return nil, nil, nil, err
		} else {
			info.Filesize = uint64(s.Size())
		}
	}
	handle, err := pcap.OpenOffline(filepath.Join(pcapDir, pcapFilename))
	if err != nil {
		return nil, nil, nil, err
	}
	defer handle.Close()
	packets := []Packet(nil)
	var storage *packetStorage
	residentBytes := int64(0)
	cleanup := func(err error) (*pcapmetadata.PcapInfo, []Packet, *packetStorage, error) {
		if storage != nil {
			storage.Close()
		}
		if memoryBudget != nil {
			*memoryBudget += residentBytes
		}
		return nil, nil, nil, err
	}
	var decoder gopacket.Decoder
	switch lt := handle.LinkType(); lt {
	case layers.LinkTypeIPv4:
		decoder = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		decoder = layers.LayerTypeIPv6
	default:
		decoder = lt
	}
	for packetIndex := uint64(0); ; packetIndex++ {
		data, ci, err := handle.ReadPacketData()
		switch err {
		case io.EOF:
			if storage != nil {
				if err := storage.writer.Flush(); err != nil {
					return cleanup(err)
				}
				storage.writer = nil
			}
			return info, packets, storage, nil
		case nil:
		default:
			return cleanup(err)
		}
		if updateInfo {
			ts := ci.Timestamp
			if info.PacketTimestampMin.IsZero() || info.PacketTimestampMin.After(ts) {
				info.PacketTimestampMin = ts
			}
			if info.PacketTimestampMax.Before(ts) {
				info.PacketTimestampMax = ts
			}
			info.PacketCount++
		}
		if metadataOnly {
			continue
		}
		if storage == nil && memoryBudget != nil && int64(len(data)) > *memoryBudget {
			file, err := os.CreateTemp(pcapDir, ".packet-spool-*.tmp")
			if err != nil {
				return cleanup(err)
			}
			storage = &packetStorage{file: file, writer: bufio.NewWriterSize(file, 256*1024)}
			for i := range packets {
				p := &packets[i]
				if err := storage.Write(p.data); err != nil {
					return cleanup(err)
				}
				p.data = nil
			}
			*memoryBudget += residentBytes
			residentBytes = 0
		}
		pcapmetadata.AddPcapMetadata(&ci, info, packetIndex)
		packet := Packet{
			decoder: decoder,
			ci:      ci,
		}
		if storage == nil {
			packet.data = data
			if memoryBudget != nil {
				*memoryBudget -= int64(len(data))
				residentBytes += int64(len(data))
			}
		} else {
			if err := storage.Write(data); err != nil {
				return cleanup(err)
			}
		}
		packets = append(packets, packet)
	}
}
