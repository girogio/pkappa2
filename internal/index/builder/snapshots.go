package builder

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

type (
	snapshot struct {
		timestamp         time.Time
		referencedPackets map[string][]uint64
		chunkCount        uint64
	}

	snapshotHeader struct {
		TimestampSec, TimestampNSec int64
		ChunkCount, NumPcaps        uint64
	}

	snapshotEntryHeader struct {
		PacketCount, FilenameLength uint64
	}
)

func loadSnapshots(filename string) ([]*snapshot, error) {
	snapshots := []*snapshot{}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	numSnapshots := uint64(0)
	if err := binary.Read(reader, binary.LittleEndian, &numSnapshots); err != nil {
		return nil, err
	}
	for ; numSnapshots > 0; numSnapshots-- {
		ss := snapshot{}
		header := snapshotHeader{}
		if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
			return nil, err
		}
		if header.TimestampNSec/1e9 != header.TimestampSec {
			return nil, fmt.Errorf("invalid timestamp: %d.%d", header.TimestampSec, header.TimestampNSec)
		}
		ss.timestamp = time.Unix(header.TimestampSec, header.TimestampNSec%1e9)
		ss.chunkCount = header.ChunkCount
		ss.referencedPackets = make(map[string][]uint64, header.NumPcaps)
		for ; header.NumPcaps > 0; header.NumPcaps-- {
			header := snapshotEntryHeader{}
			if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
				return nil, err
			}
			referencedPackets := make([]uint64, header.PacketCount)
			if err := binary.Read(reader, binary.LittleEndian, referencedPackets); err != nil {
				return nil, err
			}
			fn := make([]byte, (header.FilenameLength+7)&^uint64(7))
			if err := binary.Read(reader, binary.LittleEndian, fn); err != nil {
				return nil, err
			}
			ss.referencedPackets[string(fn[:header.FilenameLength])] = referencedPackets
		}
		snapshots = compactSnapshots(append(snapshots, &ss))
	}
	return snapshots, nil
}

func saveSnapshots(filename string, snapshots []*snapshot) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	numSnapshots := uint64(len(snapshots))
	if err := binary.Write(writer, binary.LittleEndian, &numSnapshots); err != nil {
		return err
	}
	for _, ss := range snapshots {
		header := snapshotHeader{
			TimestampSec:  ss.timestamp.Unix(),
			TimestampNSec: ss.timestamp.UnixNano(),
			ChunkCount:    ss.chunkCount,
			NumPcaps:      uint64(len(ss.referencedPackets)),
		}
		if err := binary.Write(writer, binary.LittleEndian, &header); err != nil {
			return err
		}
		for fn, rp := range ss.referencedPackets {
			header := snapshotEntryHeader{
				PacketCount:    uint64(len(rp)),
				FilenameLength: uint64(len(fn)),
			}
			if err := binary.Write(writer, binary.LittleEndian, &header); err != nil {
				return err
			}
			if err := binary.Write(writer, binary.LittleEndian, rp); err != nil {
				return err
			}
			for len(fn)%8 != 0 {
				fn += "\x00"
			}
			if _, err := writer.WriteString(fn); err != nil {
				return err
			}
		}
	}
	return writer.Flush()
}

func compactSnapshots(snapshots []*snapshot) []*snapshot {
	// Keep the oldest and newest of each three equally sized checkpoints.
	// The removed checkpoint's coverage moves to the newest one, preserving
	// the total chunk count used to select a snapshot file at startup.
	for {
		seen := make(map[uint64][]int)
		middle, newest := -1, -1
		for i, s := range snapshots {
			indices := append(seen[s.chunkCount], i)
			if len(indices) == 3 {
				middle, newest = indices[1], indices[2]
				break
			}
			seen[s.chunkCount] = indices
		}
		if middle == -1 {
			return snapshots
		}
		snapshots[newest].chunkCount += snapshots[middle].chunkCount
		copy(snapshots[middle:], snapshots[middle+1:])
		snapshots[len(snapshots)-1] = nil
		snapshots = snapshots[:len(snapshots)-1]
	}
}
