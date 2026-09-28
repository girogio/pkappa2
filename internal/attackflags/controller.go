package attackflags

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Settings are edited by the CTF setup wizard and persisted in state_dir.
// An empty URL disables the feed. Environment variables can seed settings on
// first start, but saved wizard settings take precedence thereafter.
type Settings struct {
	URL          string
	Path         string
	TickDuration string
}

type Controller struct {
	mu       sync.RWMutex
	settings Settings
	feed     *Feed
	cancel   context.CancelFunc
	done     chan struct{}
	epoch    uint64
	file     string
}

func DefaultSettings() Settings {
	return Settings{Path: "flag_ids", TickDuration: "2m"}
}

func normalizeSettings(settings Settings) Settings {
	if settings.Path == "" {
		settings.Path = "flag_ids"
	}
	if settings.TickDuration == "" {
		settings.TickDuration = "2m"
	}
	return settings
}

func NewController(stateDir string, bootstrap Settings) (*Controller, error) {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("create attack flag state directory: %w", err)
	}
	c := &Controller{file: filepath.Join(stateDir, "attack_flag_settings.json")}
	settings := normalizeSettings(bootstrap)
	data, err := os.ReadFile(c.file)
	if err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return nil, fmt.Errorf("decode attack flag settings: %w", err)
		}
		settings = normalizeSettings(settings)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if errors.Is(err, os.ErrNotExist) && settings.URL != "" {
		legacy := filepath.Join(stateDir, "attack_flag_ids.jsonl")
		archive := archiveFilename(stateDir, settings.URL, settings.Path)
		if _, err := os.Stat(archive); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Stat(legacy); err == nil {
				if err := os.Rename(legacy, archive); err != nil {
					return nil, fmt.Errorf("migrate attack flag archive: %w", err)
				}
			}
		}
	}
	feed, err := prepareFeed(stateDir, settings)
	if err != nil {
		return nil, err
	}
	c.settings = settings
	c.replaceFeed(feed)
	return c, nil
}

func prepareFeed(stateDir string, settings Settings) (*Feed, error) {
	if _, err := pathParts(settings.Path); err != nil {
		return nil, err
	}
	duration, err := time.ParseDuration(settings.TickDuration)
	if err != nil || duration < 2*time.Second {
		return nil, errors.New("attack tick duration must be a Go duration of at least 2s")
	}
	if settings.URL == "" {
		return nil, nil
	}
	return New(Config{
		URL:          settings.URL,
		Path:         settings.Path,
		TickDuration: duration,
		StateDir:     stateDir,
	})
}

func (c *Controller) Settings() Settings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.settings
}

func (c *Controller) Current() (*Feed, string, time.Duration) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	version := strconv.FormatUint(c.epoch, 10) + ":"
	if c.feed == nil {
		return nil, version + "0", 15 * time.Second
	}
	return c.feed, version + strconv.Itoa(c.feed.Generation()), c.feed.PollInterval()
}

func (c *Controller) Update(settings Settings) (Settings, error) {
	settings = normalizeSettings(settings)
	c.mu.Lock()
	defer c.mu.Unlock()
	oldFeed := c.feed
	if c.cancel != nil {
		c.cancel()
		<-c.done
	}
	feed, err := prepareFeed(filepath.Dir(c.file), settings)
	if err != nil {
		c.replaceFeed(oldFeed)
		return Settings{}, err
	}
	if err := c.save(settings); err != nil {
		c.replaceFeed(oldFeed)
		return Settings{}, err
	}
	c.settings = settings
	c.epoch++
	c.replaceFeed(feed)
	return settings, nil
}

func (c *Controller) replaceFeed(feed *Feed) {
	c.feed = feed
	c.cancel = nil
	c.done = nil
	if feed != nil {
		ctx, cancel := context.WithCancel(context.Background())
		c.cancel = cancel
		done := make(chan struct{})
		c.done = done
		go func() {
			defer close(done)
			feed.Run(ctx)
		}()
	}
}

func (c *Controller) save(settings Settings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(c.file), ".attack-flag-settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), c.file)
}

func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		<-c.done
	}
}
