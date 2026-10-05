#!/usr/bin/env bash
#
# Reserve a Testing Farm Fedora-latest guest, bring up sssd-ci-containers on
# it (picking the container image TAG interactively) and run the matching
# autofs test to reproduce the automount coredump that only shows up there.
#
# Usage: ./reserve-and-run.sh
#
# Requires:
#   - the `testing-farm` CLI (dnf copr enable @testing-farm/stable && dnf install testing-farm)
#   - TESTING_FARM_API_TOKEN exported
#   - ssh-agent running with the key you want copied to the guest added
#
# The reservation is kept alive for the full --duration after the test run
# finishes, so you can ssh back in and inspect /tmp/automount.core (inside
# the client container) by hand, e.g. with gdb.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DURATION_MINUTES=120
COMPOSE="Fedora-latest"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ServerAliveInterval=60 -o ServerAliveCountMax=3)

echo "Select the sssd-ci-containers image TAG to reproduce against:"
select TAG in "centos-10" "fedora-45"; do
    case "$TAG" in
        centos-10|fedora-45) break ;;
        *) echo "Invalid choice, pick 1 or 2." ;;
    esac
done

case "$TAG" in
    centos-10) TEST_NAME="test_autofs__new_map_entries_added_to_provider_are_visible_after_reload"
               AUTOMOUNT_BIN="/usr/sbin/automount" ;;
    fedora-45) TEST_NAME="test_autofs__works_with_some_offline_domains"
               AUTOMOUNT_BIN="/usr/bin/automount" ;;
esac

echo "Using TAG=$TAG, test=$TEST_NAME, automount=$AUTOMOUNT_BIN"

if [[ -z "${TESTING_FARM_API_TOKEN:-}" ]]; then
    cat >&2 <<'EOF'
TESTING_FARM_API_TOKEN is not set.

To obtain one:
  1. Install the CLI:
       dnf copr enable @testing-farm/stable
       dnf install testing-farm
  2. Sign in at https://testing-farm.io and open "Your Tokens" to create one.
       - Fedora/CentOS contributors: sign in via Fedora SSO. This requires
         CLA+1 (a signed Fedora contributor agreement plus membership in the
         'fedora-contributor' or 'testing-farm' group). If you hit CLA+1
         issues, contact tft@redhat.com.
       - Red Hat employees: sign in via Red Hat SSO instead.
     Details: https://docs.testing-farm.io/Testing%20Farm/0.1/onboarding.html
  3. export TESTING_FARM_API_TOKEN=<your-token>

Then re-run this script.
EOF
    exit 1
fi

if ! command -v testing-farm >/dev/null 2>&1; then
    echo "testing-farm CLI not found. Install it with:" >&2
    echo "  dnf copr enable @testing-farm/stable && dnf install testing-farm" >&2
    exit 1
fi

if [[ -z "${SSH_AUTH_SOCK:-}" ]]; then
    echo "No ssh-agent detected (SSH_AUTH_SOCK is unset)." >&2
    echo "testing-farm reserve copies your public keys to the guest and needs" >&2
    echo "ssh-agent to authenticate back into it. Run:" >&2
    echo "  eval \$(ssh-agent) && ssh-add" >&2
    exit 1
fi

WORKDIR=$(mktemp -d /tmp/tf-automount-coredump.XXXXXX)
RESERVE_LOG="$WORKDIR/reserve.log"
RESERVE_FIFO="$WORKDIR/reserve.stdin"
mkfifo "$RESERVE_FIFO"

echo "Reserving $COMPOSE for ${DURATION_MINUTES}m..."

# `testing-farm reserve` ends by exec'ing an interactive ssh session into the
# guest. Keeping stdin open (via this fifo, held open on fd 3) stops that
# session from immediately hitting EOF and exiting, which keeps the
# reservation alive in the background for the whole --duration instead of
# being released as soon as the command is backgrounded.
exec 3<>"$RESERVE_FIFO"
testing-farm reserve --compose "$COMPOSE" --duration "$DURATION_MINUTES" \
    <&3 >"$RESERVE_LOG" 2>&1 &
RESERVE_PID=$!

echo "testing-farm reserve running in background as PID $RESERVE_PID, log: $RESERVE_LOG"
echo "Waiting for the guest to become ready (can take several minutes)..."

HOST=""
for _ in $(seq 1 360); do
    if ! kill -0 "$RESERVE_PID" 2>/dev/null; then
        echo "testing-farm reserve exited early:" >&2
        sed -r 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$RESERVE_LOG" >&2
        exit 1
    fi

    candidate=$(sed -r 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$RESERVE_LOG" \
        | grep -m1 -oP 'ssh root@\K\S+' || true)
    if [[ -n "$candidate" ]]; then
        HOST="$candidate"
        break
    fi

    sleep 10
done

if [[ -z "$HOST" ]]; then
    echo "Timed out waiting for the guest to come up. See $RESERVE_LOG" >&2
    exit 1
fi

echo "Guest ready: root@$HOST"
echo "Running reproduction steps on the guest..."
if ssh "${SSH_OPTS[@]}" "root@$HOST" bash -s -- "$TAG" "$TEST_NAME" "$AUTOMOUNT_BIN" < "$SCRIPT_DIR/remote-steps.sh"; then
    remote_rc=0
else
    remote_rc=$?
fi

if [[ "$remote_rc" -ne 0 ]]; then
    cat <<EOF

remote-steps.sh failed (exit $remote_rc) on root@$HOST -- see the output above.

The reservation (PID $RESERVE_PID) is still running in the background and
keeps the guest alive for the remaining part of the ${DURATION_MINUTES} minutes.
To reconnect and investigate:
  ssh ${SSH_OPTS[*]} root@$HOST
To release it early, ssh in and run: return2testingfarm

=========================================================

To re-run the autofs test manually:

  cd /root/sssd/src/tests/system
  source /tmp/venv/bin/activate
  pytest --mh-config=./mhc.yaml -vvv -k "$TEST_NAME"

=========================================================

EOF
    exit "$remote_rc"
fi

cat <<EOF

Done. The coredump is at /tmp/automount.core inside the 'client' container
on root@$HOST.

Dropping you into the guest now. The reservation (PID $RESERVE_PID) keeps it
alive for the remaining part of the ${DURATION_MINUTES} minutes; exit the
shell to detach (it stays reserved), or run 'return2testingfarm' on it to
release early.

=========================================================

To re-run the autofs test manually:

  cd /root/sssd/src/tests/system
  source /tmp/venv/bin/activate
  pytest --mh-config=./mhc.yaml -vvv -k "$TEST_NAME"

=========================================================

To inspect the coredump:

  podman exec -it client bash
  gdb $AUTOMOUNT_BIN /tmp/automount.core

=========================================================

EOF

exec ssh "${SSH_OPTS[@]}" "root@$HOST"
