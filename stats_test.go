package main

import (
	"bytes"
	"context"
	"log"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStatsLine(t *testing.T) {
	tests := []struct {
		name string
		mem  memSnapshot
		want string
	}{
		{
			name: "all fields present",
			mem: memSnapshot{
				heap:  4_404_019,  // 4.2 MiB
				sys:   18_979_224, // 18.1 MiB
				rss:   12_582_912, // 12.0 MiB
				limit: 83_886_080, // 80.0 MiB
				numGC: 7,
			},
			want: "cache prefix=12/256 org=3/512 | mem heap=4.2MiB sys=18.1MiB rss=12.0MiB limit=80.0MiB gc=7",
		},
		{
			// Non-Linux, or /proc unreadable: the field is omitted rather than
			// reported as zero.
			name: "rss omitted when unavailable",
			mem:  memSnapshot{heap: 4_404_019, sys: 18_979_224, limit: 83_886_080, numGC: 7},
			want: "cache prefix=12/256 org=3/512 | mem heap=4.2MiB sys=18.1MiB limit=80.0MiB gc=7",
		},
		{
			name: "limit omitted when GOMEMLIMIT is unset",
			mem:  memSnapshot{heap: 4_404_019, sys: 18_979_224, rss: 12_582_912, numGC: 7},
			want: "cache prefix=12/256 org=3/512 | mem heap=4.2MiB sys=18.1MiB rss=12.0MiB gc=7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statsLine(tt.mem, 12, 3); got != tt.want {
				t.Errorf("statsLine mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestLogStatsReportsCacheSizes proves the counters are read from the live maps
// rather than being decorative.
func TestLogStatsReportsCacheSizes(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	origRead := readMem
	readMem = func() memSnapshot { return memSnapshot{heap: 1 << 20, sys: 2 << 20, numGC: 1} }
	t.Cleanup(func() { readMem = origRead })

	var buf bytes.Buffer
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(origOut); log.SetFlags(origFlags) })

	for i := range 5 {
		clock = clock.Add(time.Second)
		if _, _, err := getPrefixes(context.Background(), strconv.Itoa(3000+i)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	logStats()

	want := "cache prefix=5/256 org=0/512"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("stats line %q, want it to contain %q", buf.String(), want)
	}
}

// TestStartStatsLoggerStopsOnCancel guards against leaking the ticker goroutine
// past shutdown.
func TestStartStatsLoggerStopsOnCancel(t *testing.T) {
	origRead := readMem
	readMem = func() memSnapshot { return memSnapshot{} }
	t.Cleanup(func() { readMem = origRead })

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	// startStatsLogger emits one baseline line synchronously, then ticks.
	go func() {
		startStatsLogger(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startStatsLogger did not return")
	}

	if !strings.Contains(buf.String(), "cache prefix=") {
		t.Errorf("no baseline line emitted at startup: %q", buf.String())
	}

	// Cancelling must stop the goroutine; the race detector and goroutine
	// leak would otherwise show up here.
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestMiB(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0.0MiB"},
		{1 << 20, "1.0MiB"},
		{83_886_080, "80.0MiB"},
		{4_404_019, "4.2MiB"},
	}
	for _, tt := range tests {
		if got := mib(tt.in); got != tt.want {
			t.Errorf("mib(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestProcessRSS is Linux-specific: the container runs on Linux, where this
// must return a plausible non-zero value.
func TestProcessRSS(t *testing.T) {
	got := processRSS()
	if got == 0 {
		t.Skip("/proc/self/status unavailable on this platform")
	}
	// A running Go test process is comfortably above 1 MiB and below 10 GiB.
	if got < 1<<20 || got > 10<<30 {
		t.Errorf("implausible RSS %d bytes (%s)", got, mib(got))
	}
}
