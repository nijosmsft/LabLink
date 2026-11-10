package mcptools

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// heartbeatInterval is the wall-clock spacing of byte-progress heartbeats
// published during streaming transfers.
var heartbeatInterval = 5 * time.Second

// progressReporter is the minimal subset of *ops.Handle needed by transfer
// helpers. Tests substitute a recording fake.
type progressReporter interface {
	Progress(bytesDone, bytesTotal int64)
}

type nopProgressReporter struct{}

func (nopProgressReporter) Progress(int64, int64) {}

type transferProgress struct {
	done  atomic.Int64
	total atomic.Int64
}

func newTransferProgress(total int64) *transferProgress {
	p := &transferProgress{}
	p.total.Store(total)
	return p
}

func (p *transferProgress) Add(bytes int64) {
	p.done.Add(bytes)
}

func (p *transferProgress) SetTotal(total int64) {
	p.total.Store(total)
}

func (p *transferProgress) Snapshot() (int64, int64) {
	return p.done.Load(), p.total.Load()
}

func startTransferProgressHeartbeat(
	ctx context.Context,
	reporter progressReporter,
	notifier progressNotifier,
	progress *transferProgress,
) func() {
	if reporter == nil && notifier == nil {
		return func() {}
	}
	if reporter == nil {
		reporter = nopProgressReporter{}
	}

	hbCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				publishTransferProgress(reporter, notifier, progress)
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

func publishTransferProgress(
	reporter progressReporter,
	notifier progressNotifier,
	progress *transferProgress,
) {
	if reporter == nil {
		reporter = nopProgressReporter{}
	}
	done, total := progress.Snapshot()
	reporter.Progress(done, total)
	if notifier != nil {
		notifier(done, total)
	}
}
