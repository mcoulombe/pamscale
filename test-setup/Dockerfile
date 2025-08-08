FROM debian:bullseye-slim

# Install Postgres and dependencies
RUN apt-get update && apt-get install -y \
    postgresql postgresql-contrib bash curl gnupg lsb-release iproute2 iptables ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
