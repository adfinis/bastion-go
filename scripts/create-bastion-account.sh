#!/usr/bin/env bash

set -euo pipefail

docker compose exec -T bastion \
    /opt/bastion/bin/admin/setup-first-admin-account.sh \
    bastionadmin \
    auto < testdata/id_ed25519.pub

# enable ipv6 support
docker compose exec -T bastion \
    /usr/bin/sed -i 's/"IPv6Allowed": false,/"IPv6Allowed": true,/' \
    /etc/bastion/bastion.conf

echo "IPv6 enabled!"

# enable portforwarding support
docker compose exec -T bastion \
    /usr/bin/sed -i 's/"portForwardingEnabled": false,/"portForwardingEnabled": true,/' \
    /etc/bastion/bastion.conf

echo "Portforwarding enabled!"
