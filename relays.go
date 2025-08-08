package main

import (
	"context"
	"expvar"
	"net"

	"tailscale.com/metrics"
)

// Relay is used to proxy connections from Tailscale clients to a database server.
//
// Uses the client’s Tailscale identity to authorize access and map it
// to a database user or role, according to the grants defined in the tailnet policy file.
type Relay interface {
	// Serve listens to incoming tailscale connections on the provided listener
	// and proxies each connection to the database server in a separate session.
	Serve(net.Listener) error
	// Metrics returns metrics about the relay's operation which can be consulted on the debug endpoint.
	// Useful for monitoring and debugging.
	Metrics() expvar.Var

	// hasAccess checks whether the given Tailscale connection is authorized to access the database
	// according to the grants defined in the tailnet policy file.
	hasAccess(context.Context, net.Conn) (bool, error)
	// seedCredentials generates or fetches appropriate credentials to connect to the database
	// based on the user and database requested by the client.
	seedCredentials(context.Context) error
	// audit logs the data received from the client connection for auditing purposes.
	audit(context.Context, net.Conn) error
}

// relayMetrics holds metrics about the relay's operation
// which can be consulted on the debug endpoint.
type relayMetrics struct {
	activeSessions  expvar.Int
	startedSessions expvar.Int
	errors          metrics.LabelMap
}
