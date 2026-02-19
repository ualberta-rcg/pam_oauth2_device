#!/bin/bash
#
# Provisioning script for pam_oauth2_device with CILogon.
#
# Receives the JWT payload JSON as $1.
# Extracts the "sub" claim, hashes it with SHA-256, and creates a local
# user of the form clg_<first 12 hex chars of hash>.
#
# Prints the provisioned username to stdout (captured by the PAM module
# to set PAM_USER for the session).
#
# Exit 0 on success, non-zero on failure.
# All diagnostic output goes to stderr so it doesn't pollute the username on stdout.

set -euo pipefail

PAYLOAD="$1"

SUB=$(echo "$PAYLOAD" | python3 -c "import sys, json; print(json.load(sys.stdin)['sub'])" 2>/dev/null)

if [ -z "$SUB" ]; then
    echo "ERROR: could not extract 'sub' from JWT payload" >&2
    exit 1
fi

HASH=$(echo -n "$SUB" | sha256sum | cut -c1-12)
USERNAME="clg_${HASH}"

if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME" 2>&2
    if [ $? -ne 0 ]; then
        echo "ERROR: failed to create user $USERNAME" >&2
        exit 1
    fi
    echo "Created user $USERNAME" >&2
else
    echo "User $USERNAME already exists" >&2
fi

echo "$USERNAME"
exit 0
