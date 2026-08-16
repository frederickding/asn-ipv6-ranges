package main

import (
	"errors"
	"testing"
	"time"
)

func TestGetPrefixesCaching(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return sampleWhois, nil
	})

	_, t0, err := getPrefixes("2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", calls)
	}

	clock = clock.Add(time.Minute)
	_, t1, err := getPrefixes("2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("cache hit should not query upstream, got %d calls", calls)
	}
	if !t1.Equal(t0) {
		t.Errorf("cached timestamp changed: %v -> %v", t0, t1)
	}

	clock = clock.Add(cacheTTL)
	_, t2, err := getPrefixes("2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected refresh after TTL, got %d calls", calls)
	}
	if !t2.After(t0) {
		t.Errorf("refreshed timestamp should advance: %v -> %v", t0, t2)
	}
}

func TestGetPrefixesDoesNotCacheErrors(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return "", errors.New("dial failed")
	})

	if _, _, err := getPrefixes("2906"); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := getPrefixes("2906"); err == nil {
		t.Fatal("expected error")
	}
	if calls != 2 {
		t.Errorf("errors must not be cached, got %d calls", calls)
	}
}
