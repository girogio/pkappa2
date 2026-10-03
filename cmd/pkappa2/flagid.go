package main

import (
	"context"
	"log"
	"maps"
	"time"

	"github.com/spq/pkappa2/internal/attackflags"
	"github.com/spq/pkappa2/internal/index/manager"
)

// syncFlagIDTag updates only streams that can have changed. A new feed needs
// one full scan; later snapshots can only affect packets near or after the
// first new snapshot, and imports provide their changed stream IDs directly.
func syncFlagIDTag(ctx context.Context, mgr *manager.Manager, feed *attackflags.Feed, previous map[uint64]struct{}, full bool, since *time.Time, dirty map[uint64]struct{}) (map[uint64]struct{}, []uint64, error) {
	matches := maps.Clone(previous)
	if full || matches == nil {
		matches = make(map[uint64]struct{})
	}
	if feed == nil || feed.Generation() == 0 {
		clear(matches)
		if err := mgr.SetFlagIDMatches(nil); err != nil {
			return nil, nil, err
		}
		return matches, nil, nil
	}
	matcher, err := feed.NewMatcher()
	if err != nil {
		return nil, nil, err
	}
	defer matcher.Close()
	v := mgr.GetView()
	defer v.Release()
	var retry []uint64
	check := func(stream manager.StreamContext) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := stream.Stream().ID()
		data, err := stream.Data("")
		if err != nil {
			// A damaged stream must not prevent other streams from being tagged.
			log.Printf("sync native flag_id tag: read stream %d: %v", id, err)
			retry = append(retry, id)
			if _, ok := previous[id]; ok {
				matches[id] = struct{}{}
			}
			return nil
		}
		found, err := matcher.HasMatch(data)
		if err != nil {
			return err
		}
		if found {
			matches[id] = struct{}{}
		} else {
			delete(matches, id)
		}
		return nil
	}
	if full {
		err = v.AllStreams(ctx, check)
	} else {
		for id := range dirty {
			if err = ctx.Err(); err != nil {
				break
			}
			var stream manager.StreamContext
			stream, err = v.Stream(id)
			if err != nil {
				break
			}
			if stream.Stream() == nil {
				delete(matches, id)
				continue
			}
			if err = check(stream); err != nil {
				break
			}
		}
		if err == nil && since != nil {
			err = v.AllStreams(ctx, func(stream manager.StreamContext) error {
				if stream.Stream().LastPacket().Before(*since) {
					return nil
				}
				if _, ok := dirty[stream.Stream().ID()]; ok {
					return nil
				}
				return check(stream)
			})
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if full || !maps.Equal(matches, previous) {
		ids := make([]uint64, 0, len(matches))
		for id := range matches {
			ids = append(ids, id)
		}
		if err := mgr.SetFlagIDMatches(ids); err != nil {
			return nil, nil, err
		}
	}
	return matches, retry, nil
}

func runFlagIDTag(ctx context.Context, mgr *manager.Manager, controller *attackflags.Controller) {
	events, stop := mgr.Listen()
	defer stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastFeed *attackflags.Feed
	lastGeneration := -1
	var matches map[uint64]struct{}
	dirty := make(map[uint64]struct{})
	full := true
	for {
		feed, _, _ := controller.Current()
		generation := 0
		if feed != nil {
			generation = feed.Generation()
		}
		rescanAll := full || feed != lastFeed || generation < lastGeneration || (lastGeneration == 0 && generation > 0)
		var since *time.Time
		if !rescanAll && generation > lastGeneration {
			if at, ok := feed.ChangedSince(lastGeneration); ok {
				cutoff := at.Add(-feed.PollInterval())
				since = &cutoff
			} else {
				rescanAll = true
			}
		}
		if rescanAll || since != nil || len(dirty) != 0 {
			updated, retry, err := syncFlagIDTag(ctx, mgr, feed, matches, rescanAll, since, dirty)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("sync native flag_id tag: %v", err)
			} else {
				matches = updated
				lastFeed = feed
				lastGeneration = generation
				full = false
				clear(dirty)
				for _, id := range retry {
					dirty[id] = struct{}{}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if event.Type == "pcapProcessed" {
				for _, id := range event.ChangedStreamIDs {
					dirty[id] = struct{}{}
				}
			}
		case <-ticker.C:
		}
	}
}
