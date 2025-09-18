# ts-db-relay

A tsnet application letting Tailscale nodes access databases from anywhere using their Tailscale identity to authenticate.

This is a POC.

### Local setup

Note: setup from scratch in a new environment not tested yet. These steps likely made assumptions about pre-existing requirements.

1. Build the binary

   ```bash
    GOOS=linux GOARCH=amd64 go build -o ./cmd/ts-db-relay.exe ./...
   ```
1. Start your self-hosted tailscale server if not using https://login.tailscale.com/

   ```bash
    ./path/to/local/tailscale/server
   ```
   
1. Set the `TS_AUTHKEY` and `TS_SERVER` environment variables according to your setup

   ```bash
    export TS_AUTHKEY=tskey-xxxx # reusable ephemeral key is recommended for quick iterations
    export TS_SERVER=http://host.docker.internal:31544 # https://login.tailscale.com/ for the official Tailscale server
   ```

1. Connect your workstation to your Tailscale server

   ```bash
    tailscale up --login-server=$TS_SERVER --authkey=$TS_AUTHKEY
   ```

1. Run docker compose to start a container with your local binary and a Postgres database

   ```bash
    docker compose -f test-setup/compose.yml up --build
   ```

1. Configure the ts-db-relay capability in your tailnet policy file ($TS_SERVER/admin/acls/file)

   ```json
    {
       "tagOwners": {"tag:db-postgres": ["autogroup:admin"]},
   
       "grants": [
           {
               "src": ["insecure@example.com"],
               "dst": ["tag:db-postgres"],
               "ip":  ["tcp:5432", "tcp:80"],
   
               "app": {
                   "tailscale.test/cap/ts-db-relay": [
                       {
                           "postgres": {
                               "impersonate": {
                                   "databases": ["testdb"],
                                   "users":     ["test"],
                               },
                           },
                       },
                   ],
               },
           },
       ],
    }
   ```
   
1. Connect to the database over Tailscale, works from anywhere without credentials

    ```bash
     psql "host=<ts-db-relay-node-ip> port=5432 user=test dbname=testdb"
    ```