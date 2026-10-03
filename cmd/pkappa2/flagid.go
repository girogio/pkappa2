package main

import (
	"context"
	"log"
	"time"

	"github.com/spq/pkappa2/internal/attackflags"
	"github.com/spq/pkappa2/internal/index/manager"
)

func syncFlagIDTag(ctx context.Context, mgr *manager.Manager, feed *attackflags.Feed) error {
	if feed == nil || feed.Generation() == 0 {
		return mgr.SetFlagIDMatches(nil)
	}
	v := mgr.GetView()
	defer v.Release()
	var ids []uint64
	err := v.AllStreams(ctx, func(stream manager.StreamContext) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := stream.Data("")
		if err != nil {
			return err
		}
		matches, err := feed.Match(data)
		if err != nil {
			return err
		}
		for _, chunk := range matches {
			if len(chunk) > 0 {
				ids = append(ids, stream.Stream().ID())
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return mgr.SetFlagIDMatches(ids)
}

func runFlagIDTag(ctx context.Context, mgr *manager.Manager, controller *attackflags.Controller) {
	events, stop := mgr.Listen()
	defer stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastVersion := ""
	rescan := true
	for {
		feed, version, _ := controller.Current()
		if rescan || version != lastVersion {
			if err := syncFlagIDTag(ctx, mgr, feed); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("sync native flag_id tag: %v", err)
			} else {
				lastVersion = version
				rescan = false
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
				rescan = true
			}
		case <-ticker.C:
		}
	}
}
