"""
Command-line administration, for scripted setups:

    flask --app cybics_mgmt create-event workshop-2026 "CybICS Workshop 2026"
    flask --app cybics_mgmt import-catalog workshop-2026 path/to/ctf_config.json
    flask --app cybics_mgmt set-state workshop-2026 running
    flask --app cybics_mgmt list-events
    flask --app cybics_mgmt backup /data/backup-$(date +%F).sqlite
    flask --app cybics_mgmt login-link
    flask --app cybics_mgmt new-signing-key

The event commands live in ctf/cli.py.
"""
import os
import secrets
import time

import click
from flask import current_app

from .ctf import cli as ctf_cli
from .db import get_db, now
from .fleet import signing
from .security import audit, hash_token

BACKUP_PREFIX = "cybics-mgmt-"
KEY_SUFFIX = ".signing-key.pem"


def init_app(app):
    ctf_cli.init_app(app)

    @app.cli.command("backup")
    @click.argument("path", type=click.Path())
    @click.option("--keep", type=int, default=0,
                  help="With a directory: keep only the newest N backups in it (0 keeps all).")
    def backup(path, keep):
        """
        Write a consistent copy of the database (safe while the server runs).

        PATH is a new file, or a directory that gets a timestamped file; with
        --keep, older backups in that directory are pruned (for a cron job).
        """
        directory = path if os.path.isdir(path) else None
        if directory:
            path = os.path.join(directory, time.strftime(f"{BACKUP_PREFIX}%Y%m%d-%H%M%S.sqlite"))
        if os.path.exists(path):
            raise click.ClickException(f"{path} already exists.")
        # VACUUM INTO reads a consistent snapshot, including what still sits in
        # the WAL; copying the .sqlite file alone can miss recent writes.
        get_db().execute("VACUUM INTO ?", (path,))
        click.echo(f"Backup written to {path}.")
        # The job-signing key belongs to the backup: every device pinned it,
        # and the server does not silently create a new one.
        key = os.path.join(current_app.config["DATA_DIR"], signing.KEY_FILE)
        if os.path.exists(key):
            fd = os.open(path + KEY_SUFFIX, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with open(key, "rb") as src, os.fdopen(fd, "wb") as dst:
                dst.write(src.read())
            click.echo(f"Signing key written to {path}{KEY_SUFFIX}; restore it as /data/{signing.KEY_FILE}.")
        if directory and keep > 0:
            old = sorted(f for f in os.listdir(directory)
                         if f.startswith(BACKUP_PREFIX) and f.endswith(".sqlite"))[:-keep]
            for name in old:
                os.unlink(os.path.join(directory, name))
                if os.path.exists(os.path.join(directory, name + KEY_SUFFIX)):
                    os.unlink(os.path.join(directory, name + KEY_SUFFIX))
                click.echo(f"Removed old backup {name}.")

    @app.cli.command("new-signing-key")
    @click.confirmation_option(prompt="Every enrolled device refuses jobs until it connects again. Continue?")
    def new_signing_key():
        """Replace the job-signing key, e.g. when it is lost and there is no backup."""
        signer = signing.replace_key(current_app)
        audit("fleet_signing_key_replaced", actor="cli", fingerprint=signer.fingerprint)
        click.echo(f"New signing key {signer.fingerprint}. Devices must connect again to take jobs.")

    @app.cli.command("reset-admin-password")
    def reset_admin_password():
        """Forget the admin password set in the browser; the next visit to /admin sets a new one."""
        if current_app.config.get("ADMIN_PASSWORD"):
            raise click.ClickException("The admin password comes from MGMT_ADMIN_PASSWORD; change it there.")
        get_db().execute("DELETE FROM admin_credentials")
        audit("admin_password_reset", actor="cli")
        click.echo("Admin password removed. The next visit to /admin sets a new one; do that before anyone else can.")

    @app.cli.command("login-link")
    @click.option("--minutes", type=int, default=10, help="How long the link stays valid.")
    def login_link(minutes):
        """Print a one-time admin login link (works even while logins are rate limited)."""
        minutes = max(1, minutes)
        token = secrets.token_urlsafe(32)
        get_db().execute("INSERT INTO login_links (token_hash, expires_at) VALUES (?, ?)",
                         (hash_token(token), now() + minutes * 60))
        audit("login_link_created", actor="cli", minutes=minutes)
        base = current_app.config["PUBLIC_URL"] or "http://<server>:8000"
        click.echo(f"Open within {minutes} min, once: {base}/admin/login/link/{token}")
