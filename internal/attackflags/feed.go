package attackflags

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spq/pkappa2/internal/index"
)

const maxResponseBytes = 8 << 20
const maxIDs = 10000
const maxIDBytes = 512

type Config struct {
	URL          string
	Path         string
	TickDuration time.Duration
	StateDir     string
}

type snapshot struct {
	At  time.Time `json:"at"`
	IDs []string  `json:"ids"`
}

type snapshotIndex struct {
	at     time.Time
	offset int64
	length int
}

// Feed keeps only the current IDs and a compact archive index in memory.
// Older snapshots are loaded from the state file when a stream is viewed.
type Feed struct {
	config Config
	client *http.Client
	file   string

	mu       sync.RWMutex
	index    []snapshotIndex
	current  []string
	etag     string
	modified string
}

func New(config Config) (*Feed, error) {
	if config.URL == "" {
		return nil, errors.New("attack JSON URL is empty")
	}
	u, err := url.Parse(config.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("attack JSON URL must be an HTTP or HTTPS URL")
	}
	if _, err := pathParts(config.Path); err != nil {
		return nil, err
	}
	if config.TickDuration < 2*time.Second {
		return nil, errors.New("attack tick duration must be at least 2s")
	}
	if err := os.MkdirAll(config.StateDir, 0755); err != nil {
		return nil, fmt.Errorf("create attack flag state directory: %w", err)
	}
	f := &Feed{
		config: config,
		client: &http.Client{Timeout: min(10*time.Second, config.TickDuration/2)},
	}
	f.file = archiveFilename(config.StateDir, config.URL, config.Path)
	if err := f.loadIndex(); err != nil {
		return nil, err
	}
	return f, nil
}

func archiveFilename(stateDir, feedURL, path string) string {
	key := sha256.Sum256([]byte(feedURL + "\x00" + path))
	return filepath.Join(stateDir, "attack_flag_ids_"+hex.EncodeToString(key[:8])+".jsonl")
}

func (f *Feed) PollInterval() time.Duration { return f.config.TickDuration / 2 }

func (f *Feed) Generation() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.index)
}

func (f *Feed) Run(ctx context.Context) {
	f.fetchAndLog(ctx)
	ticker := time.NewTicker(f.PollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.fetchAndLog(ctx)
		}
	}
}

func (f *Feed) fetchAndLog(ctx context.Context) {
	if err := f.Fetch(ctx); err != nil && ctx.Err() == nil {
		log.Printf("attack flag ID feed: %v", err)
	}
}

func (f *Feed) Fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.config.URL, nil)
	if err != nil {
		return err
	}
	f.mu.RLock()
	if f.etag != "" {
		req.Header.Set("If-None-Match", f.etag)
	}
	if f.modified != "" {
		req.Header.Set("If-Modified-Since", f.modified)
	}
	f.mu.RUnlock()
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("attack JSON returned %s", resp.Status)
	}
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("attack JSON exceeds %d bytes", maxResponseBytes)
	}
	ids, err := Extract(body, f.config.Path)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Equal(ids, f.current) {
		at := time.Now().UTC()
		if len(f.index) > 0 && !at.After(f.index[len(f.index)-1].at) {
			at = f.index[len(f.index)-1].at.Add(time.Nanosecond)
		}
		if err := f.appendSnapshot(snapshot{At: at, IDs: ids}); err != nil {
			return err
		}
		f.current = ids
	}
	f.etag = resp.Header.Get("ETag")
	f.modified = resp.Header.Get("Last-Modified")
	return nil
}

func pathParts(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("attack flag ID JSON path is empty")
	}
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid attack flag ID JSON path %q", path)
		}
	}
	return parts, nil
}

// Extract supports dot-separated object keys, numeric array indexes, and *
// for all object values or array elements. The selected value can be a string,
// or an object or array containing strings.
func Extract(body []byte, path string) ([]string, error) {
	parts, err := pathParts(path)
	if err != nil {
		return nil, err
	}
	var root any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("decode attack JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("attack JSON must contain exactly one value")
	}
	// SaarCTF-style feeds expose flag IDs under flag_ids, while the ECSC 2026
	// attack feed exposes the same kind of per-service values under attack_info.
	// Keep existing saved default settings working with either feed shape.
	if path == "flag_ids" {
		if object, ok := root.(map[string]any); ok {
			if _, hasFlagIDs := object["flag_ids"]; !hasFlagIDs {
				if _, hasAttackInfo := object["attack_info"]; hasAttackInfo {
					parts = []string{"attack_info"}
				}
			}
		}
	}
	values := []any{root}
	for _, part := range parts {
		next := make([]any, 0)
		for _, value := range values {
			switch node := value.(type) {
			case map[string]any:
				if part == "*" {
					for _, v := range node {
						next = append(next, v)
					}
				} else if v, ok := node[part]; ok {
					next = append(next, v)
				}
			case []any:
				if part == "*" {
					next = append(next, node...)
				} else if n, err := strconv.Atoi(part); err == nil && n >= 0 && n < len(node) {
					next = append(next, node[n])
				}
			}
		}
		values = next
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("attack flag ID path %q matched no values", path)
	}
	seen := make(map[string]struct{})
	var visit func(any) error
	visit = func(value any) error {
		switch v := value.(type) {
		case string:
			if v == "" {
				return nil
			}
			if len(v) > maxIDBytes {
				return fmt.Errorf("attack flag ID exceeds %d bytes", maxIDBytes)
			}
			seen[v] = struct{}{}
			if len(seen) > maxIDs {
				return fmt.Errorf("attack JSON contains more than %d flag IDs", maxIDs)
			}
		case json.Number:
			return visit(v.String())
		case []any:
			for _, element := range v {
				if err := visit(element); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, element := range v {
				if err := visit(element); err != nil {
					return err
				}
			}
		case nil:
			return nil
		default:
			return fmt.Errorf("attack flag IDs must be strings, got %T", value)
		}
		return nil
	}
	for _, value := range values {
		if err := visit(value); err != nil {
			return nil, err
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func (f *Feed) loadIndex() error {
	file, err := os.Open(f.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var offset int64
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return err
		}
		if err == io.EOF {
			// Ignore an interrupted final append; the next append truncates it.
			if truncateErr := os.Truncate(f.file, offset); truncateErr != nil {
				return truncateErr
			}
			break
		}
		var record snapshot
		if err := json.Unmarshal(line, &record); err != nil {
			return fmt.Errorf("decode attack flag archive at byte %d: %w", offset, err)
		}
		if len(f.index) > 0 && record.At.Before(f.index[len(f.index)-1].at) {
			return errors.New("attack flag archive timestamps are out of order")
		}
		f.index = append(f.index, snapshotIndex{at: record.At, offset: offset, length: len(line)})
		f.current = record.IDs
		offset += int64(len(line))
	}
	return nil
}

func (f *Feed) appendSnapshot(record snapshot) error {
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	file, err := os.OpenFile(f.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	n, err := file.Write(line)
	if err != nil || n != len(line) {
		_ = file.Truncate(offset)
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Truncate(offset)
		return err
	}
	f.index = append(f.index, snapshotIndex{at: record.At, offset: offset, length: len(line)})
	return nil
}

func loadSnapshot(file *os.File, entry snapshotIndex) ([]string, error) {
	line := make([]byte, entry.length)
	if _, err := file.ReadAt(line, entry.offset); err != nil {
		return nil, err
	}
	var record snapshot
	if err := json.Unmarshal(line, &record); err != nil {
		return nil, err
	}
	return record.IDs, nil
}

// Match returns the IDs found in each data chunk. A snapshot starts at the
// time it was fetched and remains valid until the next changed snapshot. The
// first snapshot also covers older packets, since the feed may be configured
// after their capture. The following snapshot is considered for one poll
// interval to cover delay.
func (f *Feed) Match(data []index.Data) ([][]string, error) {
	result := make([][]string, len(data))
	f.mu.RLock()
	entries := slices.Clone(f.index)
	f.mu.RUnlock()
	if len(entries) == 0 {
		return result, nil
	}
	file, err := os.Open(f.file)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cache := make(map[int][]string)
	read := func(n int) ([]string, error) {
		if ids, ok := cache[n]; ok {
			return ids, nil
		}
		ids, err := loadSnapshot(file, entries[n])
		if err == nil {
			cache[n] = ids
		}
		return ids, err
	}
	for i, chunk := range data {
		at := chunk.Time
		if at.IsZero() {
			at = time.Now()
		}
		next := sort.Search(len(entries), func(n int) bool { return entries[n].at.After(at) })
		candidates := make([]int, 0, 2)
		if next > 0 {
			candidates = append(candidates, next-1)
		}
		if next == 0 || (next < len(entries) && entries[next].at.Sub(at) <= f.PollInterval()) {
			candidates = append(candidates, next)
		}
		seen := make(map[string]struct{})
		for _, n := range candidates {
			ids, err := read(n)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				if bytes.Contains(chunk.Content, []byte(id)) {
					seen[id] = struct{}{}
				}
			}
		}
		for id := range seen {
			result[i] = append(result[i], id)
		}
		slices.Sort(result[i])
	}
	return result, nil
}
