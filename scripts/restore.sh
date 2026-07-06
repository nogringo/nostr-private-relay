#!/bin/bash
set -euo pipefail

# Configuration
CONTAINER_NAME="nostr-private-relay"
DATA_DIR="./data/lmdb"
BACKUP_FILE="${1:-}"

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: $0 <path_to_backup_file.mdb.gz>" >&2
    exit 1
fi

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: Backup file '${BACKUP_FILE}' does not exist." >&2
    exit 1
fi

echo "=== Starting Restoration ==="
echo "Source file: ${BACKUP_FILE}"

# 1. Stop the container
echo "Stopping container '${CONTAINER_NAME}'..."
docker compose down

# 2. Keep a safety backup of current data if it exists
if [ -d "${DATA_DIR}" ] && [ "$(ls -A "${DATA_DIR}")" ]; then
    TEMP_BACKUP="./data/lmdb_pre_restore_$(date +%Y%m%d_%H%M%S)"
    echo "Backing up current database to ${TEMP_BACKUP} for safety..."
    mv "${DATA_DIR}" "${TEMP_BACKUP}"
fi

# Create a clean folder
mkdir -p "${DATA_DIR}"

# 3. Restore the database
echo "Decompressing and restoring database..."
gunzip -c "${BACKUP_FILE}" > "${DATA_DIR}/data.mdb"

# 4. Restart the container
echo "Restarting container..."
docker compose up -d

echo "=== Restoration completed successfully ==="
