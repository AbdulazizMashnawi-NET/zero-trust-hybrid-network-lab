#!/bin/bash
# entrypoint.sh - dispatch on $ROLE. Applies this node's host firewall then
# starts its service. Team-unique hostname is already set by compose, so it
# shows up in every prompt, packet capture, and certificate.
set -e
FW="/lab/firewall/${ROLE}.nft"
apply_fw() {
  if [ -f "$FW" ]; then
    tr -d '\r' < "$FW" > /tmp/fw.nft
    nft -f /tmp/fw.nft 2>/tmp/nft.err && echo "[fw] loaded $FW" || \
      echo "[fw] WARNING could not load $FW: $(cat /tmp/nft.err)"
  fi
}

case "$ROLE" in
  host)
    echo "[$TEAM] host $(hostname) ready - exec in and run your tools"
    exec tail -f /dev/null
    ;;
  admin)
    apply_fw
    ssh-keygen -A >/dev/null 2>&1 || true
    adduser -D -s /bin/ash netadmin 2>/dev/null || true
    echo "netadmin:$TEAM-lab" | chpasswd 2>/dev/null || true
    echo "[$TEAM] admin jump host $(hostname) - sshd on :22"
    exec /usr/sbin/sshd -D -e
    ;;
  server-db)
    apply_fw
    echo "[$TEAM] mock exam DB listening on :$DB_PORT (host firewall active)"
    exec python3 /lab/examapp/listener.py "$DB_PORT" "exam-database"
    ;;
  server-records)
    apply_fw
    python3 /lab/examapp/listener.py 9200 "records-legacy-admin" &
    exec python3 /lab/examapp/listener.py 8080 "onprem-records-api"
    ;;
  server-support)
    apply_fw
    exec python3 /lab/examapp/listener.py 22 "vendor-support-host"
    ;;
  idp)
    exec python3 /lab/idp/app.py
    ;;
  examapp)
    apply_fw
    exec python3 /lab/examapp/app.py
    ;;
  pep)
    exec python3 /lab/edge/pep.py
    ;;
  vendor)
    echo "[$TEAM] vendor endpoint $(hostname) - WireGuard config at /lab/vendor/wg0.conf"
    exec tail -f /dev/null
    ;;
  *)
    echo "unknown ROLE=$ROLE"; exec tail -f /dev/null ;;
esac
