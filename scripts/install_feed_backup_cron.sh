#!/usr/bin/env bash
# Install (or reinstall) the feeds backup trigger on the bot's box. Idempotent.
# Run this again whenever the box is replaced:  bash scripts/install_feed_backup_cron.sh
#
# - installs the cron package if missing (Debian, needs sudo)
# - starts the cron daemon if it is not running (the box has no init system)
# - adds a ~/.bashrc line that restarts cron whenever a shell opens, so a box
#   restart heals itself on the next shell
# - installs the crontab entry: :28 and :58, 06:00-22:58 plus 23:00, Pacific
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="${PT_STATE_DIR:-/workspace/pt-state}"
mkdir -p "$STATE_DIR"

if ! command -v cron >/dev/null 2>&1 && [ ! -x /usr/sbin/cron ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron >/dev/null
fi
if ! pgrep -x cron >/dev/null 2>&1; then
  sudo /usr/sbin/cron
fi

HOOK='pgrep -x cron >/dev/null 2>&1 || sudo -n /usr/sbin/cron >/dev/null 2>&1 || true  # patch-these feed backup'
touch "$HOME/.bashrc"
grep -qF '# patch-these feed backup' "$HOME/.bashrc" || echo "$HOOK" >> "$HOME/.bashrc"

LINE_ENV="CRON_TZ=America/Los_Angeles"
JOB="cd $REPO_DIR && PT_STATE_DIR=$STATE_DIR /usr/bin/python3 scripts/dispatch_feeds_backup.py >/dev/null 2>&1"
TMP="$(mktemp)"
crontab -l 2>/dev/null | grep -v 'dispatch_feeds_backup.py' | grep -v '^CRON_TZ=America/Los_Angeles$' > "$TMP" || true
{
  echo "$LINE_ENV"
  echo "28,58 6-22 * * * $JOB"
  echo "0 23 * * * $JOB"
  cat "$TMP"
} | crontab -
rm -f "$TMP"
echo "cron running: $(pgrep -x cron >/dev/null && echo yes || echo no)"
crontab -l | grep -E 'CRON_TZ|dispatch_feeds_backup'
