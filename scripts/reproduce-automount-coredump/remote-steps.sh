#!/usr/bin/env bash
#
# Runs *on* the reserved Testing Farm guest. Clones the test branches,
# brings up sssd-ci-containers, runs the flaky autofs test and pulls the
# automount coredump out of the client container.
#
# Not meant to be run by hand -- piped into
# `ssh ... bash -s -- TAG TEST_NAME AUTOMOUNT_BIN` by reserve-and-run.sh.

set -ex -o pipefail

TAG="${1:?TAG not provided}"
TEST_NAME="${2:?TEST_NAME not provided}"
AUTOMOUNT_BIN="${3:?AUTOMOUNT_BIN not provided}"

cd /root

dnf install -y git

rm -rf sssd sssd-ci-containers
git clone https://github.com/pbrezina/sssd.git
git -C sssd checkout tft

git clone https://github.com/pbrezina/sssd-ci-containers.git
git -C sssd-ci-containers checkout tmt

TAG="$TAG" /root/sssd-ci-containers/tmt/setup.sh

echo "# Installing autofs debuginfo (and dependencies) in the client container"
ci-exec --where client --user root -- bash -c '
    dnf install -y dnf-plugins-core
    dnf debuginfo-install -y autofs
' || echo "WARNING: failed to install autofs debuginfo, continuing without it"

# Same "Install system tests dependencies" step as tmt/plans/system-tests.fmf.
dnf install -y \
    ansifilter \
    cyrus-sasl-devel \
    gcc \
    git \
    libssh-devel \
    openldap-devel \
    openssl-devel \
    python3-devel \
    python3-pip \
    yq

python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
pip3 install -r /root/sssd/src/tests/system/requirements.txt

yq -i 'del(.domains[0].hosts[] | select(.role == "ad"))' /root/sssd/src/tests/system/mhc.yaml

cd /root/sssd/src/tests/system

set +e
pytest \
    --mh-config=./mhc.yaml \
    -vvv \
    -k "$TEST_NAME"
pytest_rc=$?
set -e

echo "# pytest exit code: $pytest_rc"

echo "# Coredumps known to the host (most recent last):"
coredumpctl list "$AUTOMOUNT_BIN" || true

echo "# Copying the most recent coredump from the host into the client container:"
coredumpctl dump -1 "$AUTOMOUNT_BIN" | podman exec -i client sh -c 'cat > /tmp/automount.core'

echo "# Coredump saved to /tmp/automount.core inside the client container:"
ci-exec --where client --user root -- ls -la /tmp/automount.core
