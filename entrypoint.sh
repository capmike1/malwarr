#!/bin/bash
set -e

if [ "${CLAMAV_ENABLED:-true}" = "true" ]; then
  echo "Updating ClamAV virus definitions (first run may take a few minutes)..."
  freshclam --quiet || echo "freshclam failed - continuing, will retry on next scheduled update"
fi

HOUR="${MEDIA_SCAN_START_HOUR:-01:00}"
CRON_HOUR=$(echo "$HOUR" | cut -d: -f1 | sed 's/^0//')
CRON_MIN=$(echo "$HOUR" | cut -d: -f2 | sed 's/^0//')
CRON_HOUR=${CRON_HOUR:-1}
CRON_MIN=${CRON_MIN:-0}

mkdir -p /etc/crontabs
cat > /etc/crontabs/root <<CRONEOF
$CRON_MIN $CRON_HOUR * * * python3 /app/scanner.py sweep >> /var/log/malwarr_sweep.log 2>&1
0 4 * * * freshclam --quiet >> /var/log/freshclam_update.log 2>&1
CRONEOF

echo "Media sweep scheduled daily at ${HOUR}"
crond -b -l 8

echo "Starting downloads watch loop..."
exec python3 -u /app/scanner.py watch
