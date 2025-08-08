#!/bin/bash
set -e

export PATH="/usr/lib/postgresql/13/bin:$PATH"

PGDATA="/var/lib/postgresql/data"

# Ensure PGDATA directory exists and has correct permissions
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

# Ensure ts-state directory exists and has correct permissions
mkdir -p /var/lib/ts-state
chmod 755 /var/lib/ts-state

# Create certificates directory
mkdir -p /var/lib/certs
chmod 755 /var/lib/certs

# Generate TLS certificates
echo "Generating TLS certificates..."

# Generate private key
openssl genrsa -out /var/lib/certs/server.key 2048

# Create certificate config with SANs
cat > /var/lib/certs/cert.conf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=CA
L=SF
O=Test
OU=Test
CN=localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = postgres-db
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate certificate with SANs
openssl req -new -x509 -key /var/lib/certs/server.key -out /var/lib/certs/server.crt -days 365 \
    -config /var/lib/certs/cert.conf -extensions v3_req

# Copy certificate as CA file for client verification
cp /var/lib/certs/server.crt /var/lib/certs/ca.crt

# Set proper permissions
chown -R postgres:postgres /var/lib/certs
chmod 600 /var/lib/certs/server.key
chmod 644 /var/lib/certs/server.crt /var/lib/certs/ca.crt /var/lib/certs/cert.conf

echo "TLS certificates generated with SANs."

# Write a secure pg_hba.conf that forces password auth and SSL
cat > "$PGDATA/pg_hba.conf" <<'EOF'
local   all             all                                     trust
hostssl all             all             127.0.0.1/32            md5
hostssl all             all             ::1/128                 md5
EOF

# Ensure correct permissions
chown postgres:postgres "$PGDATA/pg_hba.conf"

# Initialize database if empty
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "Initializing Postgres database..."
    su postgres -c "initdb -D $PGDATA"
fi

# Configure Postgres for SSL
echo "Configuring Postgres SSL settings..."
cat >> "$PGDATA/postgresql.conf" <<'EOF'

# SSL Configuration
ssl = on
ssl_cert_file = '/var/lib/certs/server.crt'
ssl_key_file = '/var/lib/certs/server.key'
ssl_ca_file = '/var/lib/certs/ca.crt'
EOF

chown postgres:postgres "$PGDATA/postgresql.conf"

# Start Postgres in background
echo "Starting Postgres..."
su postgres -c "postgres -D $PGDATA &"

# Wait until Postgres is ready
until pg_isready -h localhost -p 5432; do
    echo "Waiting for Postgres..."
    sleep 1
done
echo "Postgres is ready!"

# Create or update test user
echo "Creating/updating test user..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'test'
   ) THEN
      CREATE ROLE test WITH LOGIN PASSWORD 'Test4Sk8board';
   ELSE
      ALTER ROLE test WITH PASSWORD 'Test4Sk8board';
   END IF;
END
\$do\$;
EOSQL
echo "User 'test' is ready."

# Start DB relay
echo "Starting DB relay..."
TS_AUTHKEY=$TS_AUTHKEY /usr/local/bin/ts-db-relay \
--ts-control-url=$TS_SERVER \
--ts-hostname=postgres-db \
--ts-state-dir=/var/lib/ts-state \
--db-type=postgres \
--db-address=localhost:5432 \
--db-ca-file=/var/lib/certs/ca.crt \
--relay-port=5432 \
--debug-port=80 \
&

# Start a dummy relay to prove multiple cna live side by side
echo "Starting DB relay..."
TS_AUTHKEY=$TS_AUTHKEY /usr/local/bin/ts-db-relay \
--ts-control-url=$TS_SERVER \
--ts-hostname=dummy \
--ts-state-dir=/var/lib/ts-dummy-state \
--db-type=postgres \
--db-address=localhost:5432 \
--db-ca-file=/var/lib/certs/ca.crt \
--relay-port=5433 \
--debug-port=81 \
&

# Keep container alive
wait -n
