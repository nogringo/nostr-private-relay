#!/bin/bash
set -euo pipefail

CONTAINER_NAME="nostr-private-relay"
BACKUP_FILE="${1:-}"

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: $0 <path_to_export_file.jsonl[.gz]>" >&2
    exit 1
fi

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: File '${BACKUP_FILE}' does not exist." >&2
    exit 1
fi

echo "=== Starting JSONL Import ==="

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

echo "Importing events..."
# Handle compressed (.gz) or plain (.jsonl) files
if [[ "${BACKUP_FILE}" == *.gz ]]; then
    gunzip -c "${BACKUP_FILE}" | docker exec -i "${CONTAINER_NAME}" /app/relay -import
else
    docker exec -i "${CONTAINER_NAME}" /app/relay -import < "${BACKUP_FILE}"
fi

echo "=== Import completed ==="
