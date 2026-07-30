#!/bin/bash
# Purpose: Passive monitor for a public site's DNS + HTTPS reachability during an
# intermittent-outage investigation. Queries several public resolvers for each
# domain and probes HTTPS against each candidate IP directly (via --resolve, so
# each IP is tested even behind round-robin DNS). Logs ONLY failures and slow
# responses (>500ms DNS, >2s HTTPS), so the log stays readable over hours/days.
#
# Usage:  ./monitor-public-dns-https.sh <domain> [domain2 ...]
#         Edit IPS below (or export MONITOR_IPS="1.2.3.4 5.6.7.8") to probe
#         specific web-server IPs; leave empty to skip the HTTPS-by-IP checks.
# Stop:   kill the background process, or Ctrl+C.

DOMAINS=("$@")
if [ ${#DOMAINS[@]} -eq 0 ]; then
  echo "Usage: $0 <domain> [domain2 ...]" >&2
  exit 1
fi

LOG="${MONITOR_LOG:-./monitor.log}"
RESOLVERS=(8.8.8.8 1.1.1.1 9.9.9.9 75.75.75.75)
# Candidate web-server IPs to probe directly (space-separated). Optional.
IPS=(${MONITOR_IPS:-})
INTERVAL="${MONITOR_INTERVAL:-30}"

echo "[$(date -u +%FT%TZ)] Monitor started for: ${DOMAINS[*]} (logging failures + slow only)" | tee -a "$LOG"

while true; do
  TS=$(date -u +%FT%TZ)

  # DNS checks: every domain against every resolver
  for D in "${DOMAINS[@]}"; do
    for R in "${RESOLVERS[@]}"; do
      OUT=$(dig @"$R" +short A "$D" +time=2 +tries=1 2>&1)
      TIME=$(dig @"$R" A "$D" +time=2 +tries=1 2>&1 | grep "Query time" | awk '{print $4}')
      if [ -z "$OUT" ]; then
        echo "[$TS] DNS_FAIL $D via $R" | tee -a "$LOG"
      elif [ -n "$TIME" ] && [ "$TIME" -gt 500 ] 2>/dev/null; then
        echo "[$TS] DNS_SLOW $D via $R: ${TIME}ms => $OUT" | tee -a "$LOG"
      fi
    done
  done

  # HTTPS checks: hit the first domain on each candidate IP directly
  for IP in "${IPS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}|%{time_connect}|%{time_appconnect}|%{time_total}" \
      --connect-timeout 4 --max-time 8 -k \
      --resolve "${DOMAINS[0]}:443:$IP" \
      "https://${DOMAINS[0]}/" 2>&1)
    HTTP=$(echo "$STATUS" | cut -d'|' -f1)
    TOTAL=$(echo "$STATUS" | cut -d'|' -f4)
    if [ "$HTTP" != "200" ]; then
      echo "[$TS] HTTP_FAIL $IP => $STATUS" | tee -a "$LOG"
    elif [ -n "$TOTAL" ] && awk -v t="$TOTAL" 'BEGIN{exit !(t+0 > 2.0)}'; then
      echo "[$TS] HTTP_SLOW $IP => total=${TOTAL}s" | tee -a "$LOG"
    fi
  done

  sleep "$INTERVAL"
done
