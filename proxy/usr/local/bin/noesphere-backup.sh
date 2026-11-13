#!/bin/bash
# Daily snapshot of the gateway state: SQLite DB, proxy code, systemd unit and nginx config.
# One file per day (same-day runs overwrite), so growth is bounded without deletion logic.
set -e
D=$(date +%F)
mkdir -p /opt/noesphere/backups
sqlite3 /opt/noesphere/noesphere.db ".backup /opt/noesphere/backups/noesphere-$D.db"
cp /opt/noesphere/proxy.py /opt/noesphere/backups/proxy-$D.py
tar czf /opt/noesphere/backups/cfg-$D.tgz \
  /etc/systemd/system/noesphere.service \
  /etc/nginx/sites-available /etc/nginx/snippets 2>/dev/null
echo "$(date -Is) backup $D ok"
