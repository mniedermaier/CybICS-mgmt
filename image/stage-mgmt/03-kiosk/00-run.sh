#!/bin/bash -e

# Runs on the build host; files go into the image's root filesystem.
install -m 755 files/cybics-mgmt-kiosk "${ROOTFS_DIR}/usr/local/bin/cybics-mgmt-kiosk"
install -m 644 files/cybics-mgmt-kiosk.pam "${ROOTFS_DIR}/etc/pam.d/cybics-mgmt-kiosk"
install -m 644 files/cybics-mgmt-kiosk.service "${ROOTFS_DIR}/etc/systemd/system/cybics-mgmt-kiosk.service"
