package main

import (
	"context"
	"errors"
	"log"
	"time"

	"asn-ipv6-ranges/internal/cymrudns"
	"asn-ipv6-ranges/internal/peeringdb"
	"asn-ipv6-ranges/internal/radb"
)

// peeringdbVerifyTimeout bounds the startup key check. Generous relative to
// the package's own 10s client timeout, because nothing waits on this: it is
// better to give a slow start-of-day PeeringDB the time to answer than to
// record an inconclusive result we will not retry.
const peeringdbVerifyTimeout = 30 * time.Second

// logDataSources reports, once at startup, every upstream this process will
// query and how it is configured.
//
// None of these sources can be turned off — they are gated by per-host rate
// budgets, not by configuration — so the line is not a list of toggles. Its
// job is to make the *configuration* visible in the log of a fresh pod: which
// resolver Cymru lookups will actually use, and whether the API key an
// operator believes they set was picked up at all. Getting that wrong is
// otherwise invisible until someone correlates traffic with rate limits.
func logDataSources() {
	resolver := getenv(cymrudns.ResolverEnv)
	if resolver == "" {
		resolver = cymrudns.DefaultResolver + " (default)"
	}

	keyState := "no api key (anonymous rate limit)"
	if getenv(peeringdb.KeyEnv) != "" {
		keyState = "api key set, verifying"
	}

	log.Printf("data sources: prefixes=%s | org=%s (resolver %s), %s (%s), RIR whois, RDAP",
		radb.Host, cymrudns.Host, resolver, peeringdb.Host, keyState)
}

// startPeeringDBKeyCheck verifies the configured PeeringDB API key in the
// background, and drops it if PeeringDB refuses it.
//
// A bad key is worse than no key. Every lookup still works — the key only
// raises a rate limit, it is never required — so nothing visibly breaks, while
// budgetFor sees a non-empty key and picks peeringdbAuthBudget's higher rate
// for a process with no working credential. That is how this service would
// start over-querying PeeringDB without anyone noticing.
//
// The check is non-blocking and never fatal: it runs in its own goroutine so a
// slow or unreachable PeeringDB cannot delay the listener, and every outcome is
// a log line rather than an exit. An operator's key being wrong is a reason to
// warn them, not a reason to refuse to serve prefixes.
func startPeeringDBKeyCheck(ctx context.Context) {
	if getenv(peeringdb.KeyEnv) == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(ctx, peeringdbVerifyTimeout)
		defer cancel()

		// Through the budget like every other outbound call, so this one
		// request is accounted for rather than being a hole in the invariant
		// withUpstreamBudget exists to keep.
		_, err := withUpstreamBudget(peeringdb.Host, func() (struct{}, error) {
			return struct{}{}, orgPeeringDBVerify(ctx, peeringDBAPIKey())
		})

		switch {
		case err == nil:
			log.Printf("%s: api key verified", peeringdb.Host)

		case errors.Is(err, peeringdb.ErrInvalidKey):
			// Order matters: stop handing out the key first, then discard the
			// limiter built from it, so the rebuilt one reads the new state.
			peeringdbKeyRejected.Store(true)
			forgetLimiter(peeringdb.Host)
			// %v already reads "api key rejected: ..." — the sentinel's own
			// text — so the line does not repeat it.
			log.Printf("%s: %v; it will not be used, continuing anonymously at the lower rate limit",
				peeringdb.Host, err)

		default:
			// Inconclusive, and this is the branch that matters: a timeout, a
			// 5xx, or a DNS hiccup says nothing about the key. Disabling it
			// here would throw away a working credential over one bad minute
			// upstream, with no retry to recover it.
			log.Printf("%s: could not verify api key (%v); keeping it and continuing",
				peeringdb.Host, err)
		}
	}()
}
