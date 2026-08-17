package main

import (
	"sync/atomic"

	"asn-ipv6-ranges/internal/peeringdb"
)

// peeringdbKeyRejected records that the startup check proved the configured
// API key is one PeeringDB will not accept. Set at most once, seconds after
// startup, and read on every PeeringDB call — hence atomic rather than a mutex.
//
// It is deliberately one-way: nothing clears it. A key that was rejected is
// rejected for this process's life, and restarting is how an operator retries
// after fixing the environment.
var peeringdbKeyRejected atomic.Bool

// peeringDBAPIKey returns the API key to send with PeeringDB requests, or the
// empty string once verification has proved it unusable.
//
// Every PeeringDB call site reads the key through here rather than from the
// environment directly. That is the whole mechanism: without a single
// accessor, a rejected key comes straight back on the next os.Getenv, and
// budgetFor keeps choosing the authenticated rate limit for a process that has
// no working credential.
func peeringDBAPIKey() string {
	if peeringdbKeyRejected.Load() {
		return ""
	}
	return getenv(peeringdb.KeyEnv)
}
