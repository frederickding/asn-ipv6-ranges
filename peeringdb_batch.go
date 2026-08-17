package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"asn-ipv6-ranges/internal/peeringdb"
)

// This file implements opportunistic batching for forced src=peeringdb
// lookups: when several requests for different ASNs are genuinely
// concurrent, they share one PeeringDB call instead of one each.
//
// Every forced-peeringdb lookup goes through lookupPeeringDBBatched (see
// resolveOrgName's srcPeeringDB case), and it alone decides fast-path versus
// batch — by checking whether anything is *actually* in flight right now
// (peeringdbPending/peeringdbBusy), not by guessing from a request-rate
// counter. That distinction matters: an earlier version gated batching on a
// requests-per-second threshold and let calls below it bypass this file
// entirely, straight to lookupPeeringDB. That created two uncoordinated
// entry points into the same tightly-budgeted upstream — live smoke-testing
// against the real PeeringDB API caught it directly: a burst of concurrent
// requests fragmented into several independent direct calls that raced each
// other for the concurrency=1 budget slot, instead of merging into the one
// combined call batching exists to produce. Routing everything through one
// place with one piece of coordinating state is what makes "nothing else in
// flight" an actual guarantee rather than a per-path guess.
//
// It is never used for the auto chain's own PeeringDB step, which always
// calls lookupPeeringDB directly — auto spreads load across four sources per
// ASN already, so it is far less likely to need batching, and mixing
// cross-ASN batching into auto's per-ASN fallback chain would complicate
// that logic for no real benefit.

// peeringdbMaxBatch mirrors peeringdb.LookupOrgNames' own cap — kept here too
// so a round is never assembled larger than PeeringDB will actually accept.
const peeringdbMaxBatch = 150

// peeringdbBatchTimeout bounds one round's PeeringDB calls. It is independent
// of any individual caller's context — see runPeeringDBBatch — and longer
// than a single lookup's timeout because one round can be answering up to
// peeringdbMaxBatch ASNs across two HTTP requests.
const peeringdbBatchTimeout = 20 * time.Second

type peeringdbBatchReq struct {
	asn string
	res chan peeringdbBatchResult
}

type peeringdbBatchResult struct {
	name string
	err  error
}

var (
	peeringdbBatchMu sync.Mutex
	peeringdbPending []peeringdbBatchReq
	peeringdbBusy    bool // a dispatch round's HTTP calls are currently running
	peeringdbKick    = make(chan struct{}, 1)
)

// lookupPeeringDBBatched is the sole entry point for a forced src=peeringdb
// lookup (see resolveOrgName's srcPeeringDB case) — every such request comes
// through here, which is what lets it tell whether it is genuinely alone.
//
// A request that arrives with nothing already queued and no round in flight
// bypasses the queue entirely and takes the plain lookupPeeringDB path: this
// is what guarantees an uncontended request is never held up waiting for
// company that may never arrive. It still marks itself busy for the
// duration, so a second request arriving a moment later — genuinely
// concurrent with the first, just not quite simultaneous — correctly finds a
// round "in flight" and queues to be merged with whatever else arrives
// before the dispatcher fires the next one, rather than also taking its own
// solo fast path.
func lookupPeeringDBBatched(ctx context.Context, asn string) (orgResult, error) {
	peeringdbBatchMu.Lock()
	if len(peeringdbPending) == 0 && !peeringdbBusy {
		peeringdbBusy = true
		peeringdbBatchMu.Unlock()

		res, err := lookupPeeringDB(ctx, asn)

		peeringdbBatchMu.Lock()
		peeringdbBusy = false
		stillPending := len(peeringdbPending) > 0
		peeringdbBatchMu.Unlock()
		// Anyone who queued up while this was running (they must have — busy
		// was true the whole time, so nothing could take the fast path
		// instead) needs a kick: nothing else will wake the dispatcher for
		// them otherwise.
		if stillPending {
			select {
			case peeringdbKick <- struct{}{}:
			default:
			}
		}
		return res, err
	}
	ch := make(chan peeringdbBatchResult, 1)
	peeringdbPending = append(peeringdbPending, peeringdbBatchReq{asn: asn, res: ch})
	peeringdbBatchMu.Unlock()

	select {
	case peeringdbKick <- struct{}{}:
	default: // dispatcher is already awake or mid-round
	}

	select {
	case r := <-ch:
		if r.err != nil {
			return orgResult{}, fmt.Errorf("%s: %w", peeringdb.Host, r.err)
		}
		return orgResult{name: r.name, source: peeringdb.Host}, nil
	case <-ctx.Done():
		// Leaves the round running for everyone else, same as group.do's
		// documented behaviour for an abandoned waiter.
		return orgResult{}, ctx.Err()
	}
}

// startPeeringDBBatcher runs the single dispatcher goroutine for the process
// lifetime, alongside startCacheReaper.
//
// On each kick it drains and fires at most one round, then stops — it does
// not loop trying to drain everything immediately. That matters: a kick can
// arrive while a fast-path call in lookupPeeringDBBatched is already
// mid-flight (peeringdbBusy true), and firing a second round concurrently
// with it would mean two real outbound PeeringDB calls competing for the
// same tight concurrency budget instead of one call answering both — exactly
// the fragmentation batching exists to avoid. So a kick that finds busy true
// is a no-op; whoever clears busy (here, or the fast path) re-kicks if work
// is still waiting, and this goroutine picks it up on the next iteration.
func startPeeringDBBatcher(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-peeringdbKick:
			}

			peeringdbBatchMu.Lock()
			if len(peeringdbPending) == 0 || peeringdbBusy {
				peeringdbBatchMu.Unlock()
				continue
			}
			batch := peeringdbPending
			if len(batch) > peeringdbMaxBatch {
				peeringdbPending, batch = batch[peeringdbMaxBatch:], batch[:peeringdbMaxBatch]
			} else {
				peeringdbPending = nil
			}
			peeringdbBusy = true
			peeringdbBatchMu.Unlock()

			runPeeringDBBatch(batch)

			peeringdbBatchMu.Lock()
			peeringdbBusy = false
			stillPending := len(peeringdbPending) > 0
			peeringdbBatchMu.Unlock()
			if stillPending {
				select {
				case peeringdbKick <- struct{}{}:
				default:
				}
			}
		}
	}()
}

// runPeeringDBBatch fires one round's PeeringDB call(s) and delivers a result
// to every request in the batch.
//
// It uses its own timeout derived from context.Background(), not any
// individual caller's ctx: the callers waiting on this batch are a mix of
// different requests, some of which may have their own context cancelled
// while this is in flight (see lookupPeeringDBBatched's ctx.Done() case) —
// the batch itself must not be cut short just because one of them did.
func runPeeringDBBatch(batch []peeringdbBatchReq) {
	ctx, cancel := context.WithTimeout(context.Background(), peeringdbBatchTimeout)
	defer cancel()

	asns := make([]string, len(batch))
	for i, r := range batch {
		asns[i] = r.asn
	}
	apiKey := getenv(peeringdb.KeyEnv)
	names, err := withUpstreamBudget(peeringdb.Host, func() (map[string]string, error) {
		return orgPeeringDBBatchLookup(ctx, asns, apiKey)
	})
	for _, r := range batch {
		switch {
		case err != nil:
			r.res <- peeringdbBatchResult{err: err}
		case names[r.asn] == "":
			r.res <- peeringdbBatchResult{err: fmt.Errorf("no organization found for AS%s", r.asn)}
		default:
			r.res <- peeringdbBatchResult{name: names[r.asn]}
		}
	}
}
