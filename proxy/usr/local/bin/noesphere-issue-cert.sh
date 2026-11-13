#!/bin/bash
# Issue the public certificate, then place it where nginx already looks for it.
#
# Let's Encrypt rate-limits new certificates per registered domain (50 / 168h), which
# `l.cd` had exhausted, so this is safe to run repeatedly: it exits immediately once a
# long-lived cert is already installed, and disables its own timer after a success.
set -u
LOG=/var/log/noesphere-cert.log
LIVE=/etc/letsencrypt/live/noe.l.cd

echo "$(date -Is) attempt" >> "$LOG"

if [ -f "$LIVE/fullchain.pem" ] && \
   openssl x509 -in "$LIVE/fullchain.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
  echo "$(date -Is) certificate already valid, nothing to do" >> "$LOG"
  exit 0
fi

if certbot certonly --webroot -w /var/www/html \
     -d noe.l.cd -d www.noe.l.cd -d api.noe.l.cd \
     --non-interactive --agree-tos --register-unsafely-without-email \
     --deploy-hook 'install -m 644 $RENEWED_LINEAGE/fullchain.pem /etc/ssl/certs/noe.l.cd.fullchain.pem; install -m 600 $RENEWED_LINEAGE/privkey.pem /etc/ssl/private/noe.l.cd.key; systemctl reload nginx' \
     >> "$LOG" 2>&1; then
  # make sure the files are in place even if the hook did not fire
  install -m 644 "$LIVE/fullchain.pem" /etc/ssl/certs/noe.l.cd.fullchain.pem
  install -m 600 "$LIVE/privkey.pem"   /etc/ssl/private/noe.l.cd.key
  systemctl reload nginx || true
  echo "$(date -Is) ISSUED OK" >> "$LOG"
  systemctl disable --now noesphere-cert.timer >> "$LOG" 2>&1 || true
  exit 0
fi

echo "$(date -Is) attempt failed, will retry" >> "$LOG"
exit 1
