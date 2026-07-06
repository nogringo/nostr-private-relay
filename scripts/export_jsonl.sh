#!/bin/bash
set -euo pipefail

CONTAINER_NAME="nostr-private-relay"
BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/export_${TIMESTAMP}.jsonl.gz"

echo "=== Starting JSONL Export ==="
mkdir -p "${BACKUP_DIR}"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

echo "Exporting events to JSONL..."
if docker exec -i "${CONTAINER_NAME}" /app/relay -export | gzip > "${BACKUP_FILE}"; then
    echo "Export successful: ${BACKUP_FILE}"
    echo "Number of events exported: $(zcat "${BACKUP_FILE}" | wc -l)"
    echo "Archive size: $(du -h "${BACKUP_FILE}" | cut -f1)"
else
    echo "Error during export!" >&2
    rm -f "${BACKUP_FILE}"
    exit 1
fi
echo "=== Export completed ==="
