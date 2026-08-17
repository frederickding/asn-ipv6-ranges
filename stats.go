package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// statsInterval is how often cache and memory usage are logged.
const statsInterval = 5 * time.Minute

// memSnapshot is the memory picture reported in the stats line. Collection is
// separated from formatting so the line can be asserted against fixed values.
type memSnapshot struct {
	heap  uint64 // live heap
	sys   uint64 // total obtained from the OS
	rss   uint64 // resident set size; 0 when unavailable
	limit uint64 // GOMEMLIMIT; 0 when unset
	numGC uint32
}

// readMem is a test seam, like nowFunc and getenv.
var readMem = liveMemSnapshot

func liveMemSnapshot() memSnapshot {
	// ReadMemStats briefly stops the world. That is irrelevant once every five
	// minutes on a heap this size, but it is why this must not move onto a
	// request path.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// Passing -1 reports the current limit without changing it.
	limit := debug.SetMemoryLimit(-1)
	var lim uint64
	// math.MaxInt64 is the "no limit" sentinel; reporting it would be noise.
	if limit > 0 && limit != 1<<63-1 {
		lim = uint64(limit)
	}

	return memSnapshot{
		heap:  ms.HeapAlloc,
		sys:   ms.Sys,
		rss:   processRSS(),
		limit: lim,
		numGC: ms.NumGC,
	}
}

// processRSS reads the resident set size from /proc, returning 0 where that is
// unavailable.
//
// RSS is reported alongside the Go heap because it is what the kernel OOM-kills
// on and what a container memory limit governs. HeapAlloc alone understates it:
// it excludes the binary, stacks, and memory the runtime has not returned.
func processRSS() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, found := strings.CutPrefix(line, "VmRSS:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		// "VmRSS:  12345 kB"
		if len(fields) < 1 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

func mib(b uint64) string {
	return fmt.Sprintf("%.1fMiB", float64(b)/(1<<20))
}

// statsLine renders the periodic stats line. Cache occupancy is reported
// against capacity, as /-/status does, so a cache pinned at its limit is
// visible as eviction pressure over time rather than as a flat number.
func statsLine(m memSnapshot, prefixN, orgN int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "cache prefix=%d/%d org=%d/%d | mem heap=%s sys=%s",
		prefixN, prefixCacheMaxEntries, orgN, orgCacheMaxEntries, mib(m.heap), mib(m.sys))
	if m.rss > 0 {
		fmt.Fprintf(&b, " rss=%s", mib(m.rss))
	}
	if m.limit > 0 {
		fmt.Fprintf(&b, " limit=%s", mib(m.limit))
	}
	fmt.Fprintf(&b, " gc=%d", m.numGC)
	return b.String()
}

// logStats emits one stats line to the operational log on stderr.
func logStats() {
	cacheMu.RLock()
	prefixN := len(cache)
	cacheMu.RUnlock()

	orgCacheMu.RLock()
	orgN := len(orgCache)
	orgCacheMu.RUnlock()

	log.Print(statsLine(readMem(), prefixN, orgN))
}

// startStatsLogger logs cache and memory usage every statsInterval until ctx is
// cancelled, following the same pattern as startCacheReaper.
//
// One line is emitted immediately so there is a baseline in the log without
// waiting out the first interval.
func startStatsLogger(ctx context.Context) {
	logStats()
	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logStats()
			}
		}
	}()
}
