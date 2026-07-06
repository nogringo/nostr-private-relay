#!/bin/bash
set -euo pipefail

# Configuration
CONTAINER_NAME="nostr-private-relay"
BACKUP_DIR="./backups"
RETENTION_DAYS=7
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/backup_${TIMESTAMP}.mdb.gz"

echo "=== Starting LMDB Backup ==="

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"

# Check if the container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

# Perform hot copy with mdb_copy and compress on the fly
# Note: docker exec is used WITHOUT the -t flag to avoid binary stream corruption (CRLF translation)
echo "Extracting and compacting database..."
if docker exec -i "${CONTAINER_NAME}" mdb_copy -c /app/data/lmdb - | gzip > "${BACKUP_FILE}"; then
    echo "Backup successful: ${BACKUP_FILE}"
    echo "Compressed size: $(du -h "${BACKUP_FILE}" | cut -f1)"
else
    echo "Error during backup!" >&2
    rm -f "${BACKUP_FILE}"
    exit 1
fi

# Retention policy: Remove backups older than N days
echo "Applying retention policy (keeping last ${RETENTION_DAYS} days)..."
find "${BACKUP_DIR}" -name "backup_*.mdb.gz" -type f -mtime +${RETENTION_DAYS} -delete

echo "=== Backup completed successfully ==="
