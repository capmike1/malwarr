#!/bin/bash
set -e

PUID="${PUID:-99}"
PGID="${PGID:-100}"

if ! getent group "$PGID" >/dev/null 2>&1; then
  addgroup -g "$PGID" appgroup
fi
APPGROUP=$(getent group "$PGID" | cut -d: -f1)

if ! getent passwd "$PUID" >/dev/null 2>&1; then
  adduser -D -H -u "$PUID" -G "$APPGROUP" -s /bin/bash appuser
fi
APPUSER=$(getent passwd "$PUID" | cut -d: -f1)

echo "Running as ${APPUSER}:${APPGROUP} (${PUID}:${PGID})"

# defensive chown of container-internal paths only - never touches
# bind-mounted host directories' existing ownership beyond what's needed
# for a first run against an empty volume
mkdir -p /var/lib/clamav /state /quarantine
chown -R "$PUID":"$PGID" /var/lib/clamav /state 2>/dev/null || true

if [ "${CLAMAV_ENABLED:-true}" = "true" ]; then
  echo "Updating ClamAV virus definitions (first run may take a few minutes)..."
  su-exec "$PUID":"$PGID" freshclam --quiet || echo "freshclam failed - continuing, will retry on next scheduled update"
fi

HOUR="${MEDIA_SCAN_START_HOUR:-01:00}"
CRON_HOUR=$(echo "$HOUR" | cut -d: -f1 | sed 's/^0//')
CRON_MIN=$(echo "$HOUR" | cut -d: -f2 | sed 's/^0//')
CRON_HOUR=${CRON_HOUR:-1}
CRON_MIN=${CRON_MIN:-0}

mkdir -p /etc/crontabs
cat > /etc/crontabs/root <<CRONEOF
$CRON_MIN $CRON_HOUR * * * su-exec $PUID:$PGID python3 -u /app/scanner.py sweep >> /var/log/malwarr_sweep.log 2>&1
0 4 * * * su-exec $PUID:$PGID freshclam --quiet >> /var/log/freshclam_update.log 2>&1
CRONEOF

echo "Media sweep scheduled daily at ${HOUR}"
crond -b -l 8

echo "Starting downloads watch loop..."
exec su-exec "$PUID":"$PGID" python3 -u /app/scanner.py watch
