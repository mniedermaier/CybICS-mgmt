// Follow the current event on /scoreboard, the page a screen nobody touches
// shows (the HDMI output of the Raspberry Pi image): reload when the server
// names another event, or none, than the one on screen. The scoreboard
// itself keeps polling its own event in scoreboard.js.
(function () {
  "use strict";
  const root = document.querySelector("[data-follow]");
  if (!root) return;
  const url = root.dataset.follow;
  const shown = root.dataset.slug || null;
  const POLL_MS = 15000;

  async function check() {
    try {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) return;   // a server restart: keep what is on screen
      const data = await r.json();
      if ((data.slug || null) !== shown) window.location.reload();
    } catch (e) {
      // unreachable for now; try again at the next poll
    }
  }

  setInterval(() => { if (!document.hidden) check(); }, POLL_MS);
})();
