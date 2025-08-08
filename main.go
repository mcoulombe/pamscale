package main

import (
	"expvar"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	tailscaleControlURL = flag.String("ts-control-url", "https://login.tailscale.com/", "Tailscale control server URL (if empty, uses default)")
	tailscaleHostname   = flag.String("ts-hostname", "ts-db-postgresRelay", "Device name to use in Tailscale")
	tailscaleStateDir   = flag.String("ts-state-dir", "", "Directory in which to store the Tailscale auth state")

	databaseType    = flag.String("db-type", "", "Type of database to connect to (currently only 'postgres' is supported)") // TODO should be inferred using databaseAddress
	databaseAddress = flag.String("db-address", "", "Address of the database target, in host:port format")
	databaseCAFile  = flag.String("db-ca-file", "", "File containing the PEM-encoded CA certificate for the upstream database")

	relayPort = flag.Int("relay-port", 0, "Listening port for client connections")
	debugPort = flag.Int("debug-port", 0, "Listening port for debug/metrics endpoint")
)

func main() {
	flag.Parse()

	if *tailscaleStateDir == "" {
		log.Fatal("missing --ts-state-dir")
	}
	if *databaseType == "" {
		log.Fatal("missing --db-type")
	}
	if *databaseAddress == "" {
		log.Fatal("missing --db-address")
	}
	if *databaseCAFile == "" {
		log.Fatal("missing --db-ca-file")
	}
	if *relayPort == 0 {
		log.Fatal("missing --relay-port")
	}

	if os.Getenv("TS_AUTHKEY") == "" {
		log.Print("Note: you need to run this with TS_AUTHKEY=... the first time, to join your tailnet of choice.")
	}

	tsServer := &tsnet.Server{
		ControlURL: *tailscaleControlURL,
		Hostname:   *tailscaleHostname,
		Dir:        *tailscaleStateDir,
	}

	tsClient, err := tsServer.LocalClient()
	if err != nil {
		log.Fatalf("unable to instantiate Tailscale Local tsClient: %v", err)
	}

	var relay Relay
	switch *databaseType {
	case "postgres":
		relay, err = newPostgresRelay(*databaseAddress, *databaseCAFile, tsClient)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported --db-type %q", *databaseType)
	}

	expvar.Publish(*tailscaleHostname, relay.Metrics())

	if *debugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		srv := &http.Server{
			Handler: mux,
		}
		debugListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", *debugPort))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Printf("serving debug access to %s on port %d", *databaseAddress, *debugPort)
			log.Fatal(srv.Serve(debugListener))
		}()
	}

	relayListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", *relayPort))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving access to %s on port %d", *databaseAddress, *relayPort)
	log.Fatal(relay.Serve(relayListener))
}
