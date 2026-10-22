"""The projector-friendly public scoreboard page."""
from flask import abort, current_app, render_template

from ..db import get_db
from ..public import bp
from . import logic as ctf
from .api import public_board, public_scoreboard


@bp.get("/scoreboard/<slug>")
def scoreboard(slug):
    db = get_db()
    event = ctf.get_event_by_slug(db, slug)
    if not public_scoreboard(event):
        abort(404)
    board, recent = public_board(db, event)
    return render_template("scoreboard.html", event=event, board=board, recent=recent)


@bp.get("/scoreboard")
def scoreboard_current():
    """
    Whatever event is current, for a screen nobody touches (the HDMI output
    of the Raspberry Pi image): it follows the server to the next event, and
    waits on a page of its own while there is none.
    """
    db = get_db()
    event = ctf.current_public_event(db)
    if event is None:
        return render_template("scoreboard_wait.html", public_url=current_app.config["PUBLIC_URL"])
    board, recent = public_board(db, event)
    return render_template("scoreboard.html", event=event, board=board, recent=recent, follow=True)
