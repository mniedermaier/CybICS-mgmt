#!/bin/bash -e

# The kiosk runs as a user of its own, without a password or a shell: it
# only shows a public page, so it gets nothing else.
if ! id cybics-kiosk >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/cybics-kiosk --shell /usr/sbin/nologin cybics-kiosk
fi
for group in video render input; do
    if getent group "$group" >/dev/null; then
        usermod -aG "$group" cybics-kiosk
    fi
done

# Started at every boot; it runs only if cybics-mgmt-config switched it on.
systemctl enable cybics-mgmt-kiosk.service
