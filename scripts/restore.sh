#!/bin/bash
set -euo pipefail

# Configuration
SERVICE_NAME="private-relay"
BACKUP_DIR="./backups"
BACKUP_FILE="${1:-}"

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: $0 <path_to_backup_file.mdb.gz>" >&2
    exit 1
fi

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: Backup file '${BACKUP_FILE}' does not exist." >&2
    exit 1
fi

umask 077

# The database lives in a named volume, only reachable from a container mounting it
run_in_volume() {
    docker compose run --rm -T --no-deps --entrypoint sh "${SERVICE_NAME}" -c "$1"
}

echo "=== Starting Restoration ==="
echo "Source file: ${BACKUP_FILE}"

# 1. Check the archive before touching anything
echo "Checking backup integrity..."
gunzip -t "${BACKUP_FILE}"

# 2. Stop the relay
echo "Stopping service '${SERVICE_NAME}'..."
docker compose stop "${SERVICE_NAME}"

# 3. Keep a safety backup of current data if it exists
if run_in_volume 'test -s /app/data/lmdb/data.mdb'; then
    mkdir -p "${BACKUP_DIR}"
    SAFETY_FILE="${BACKUP_DIR}/pre_restore_$(date +%Y%m%d_%H%M%S).mdb.gz"
    echo "Backing up current database to ${SAFETY_FILE} for safety..."
    if ! run_in_volume 'mdb_copy -c /app/data/lmdb' | gzip > "${SAFETY_FILE}"; then
        echo "Error during safety backup, nothing was restored. The relay is still stopped." >&2
        rm -f "${SAFETY_FILE}"
        exit 1
    fi
fi

# 4. Restore the database
echo "Decompressing and restoring database..."
gunzip -c "${BACKUP_FILE}" | run_in_volume '
    cd /app/data/lmdb &&
    cat > data.mdb.restoring &&
    mv data.mdb.restoring data.mdb &&
    rm -f lock.mdb'

# 5. Restart the relay
echo "Restarting service..."
docker compose up -d

echo "=== Restoration completed successfully ==="
