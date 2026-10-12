// Portal colour theme: light, dark or system (the default).
//
// Loaded render-blocking from <head> on every page (package nav's
// "page.head"; same-origin, so CSP script-src 'self' allows it and nothing
// is inline). The first part runs before the body is parsed and sets
// <html data-theme="light|dark"> from localStorage, so a stored choice
// never flashes the other palette. "system" removes the attribute and
// portal.css follows prefers-color-scheme. Without JavaScript the toggle
// stays hidden and the page follows the system setting.
//
// The toggle (nav "theme.toggle") is a group of three buttons with
// data-theme-choice and aria-pressed; they are real <button>s, so Tab,
// Enter and Space work without extra key handling.
(function () {
  "use strict";

  var KEY = "mcp-gateway-theme";
  var root = document.documentElement;

  function valid(v) { return v === "light" || v === "dark" ? v : "system"; }

  function load() {
    try { return valid(window.localStorage.getItem(KEY)); } catch (e) { return "system"; }
  }

  function store(choice) {
    try {
      if (choice === "system") { window.localStorage.removeItem(KEY); } else { window.localStorage.setItem(KEY, choice); }
    } catch (e) { /* storage blocked: the choice lasts for this page only */ }
  }

  function apply(choice) {
    if (choice === "system") { root.removeAttribute("data-theme"); } else { root.setAttribute("data-theme", choice); }
  }

  var current = load();
  apply(current);

  function sync() {
    var buttons = document.querySelectorAll("[data-theme-choice]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", buttons[i].getAttribute("data-theme-choice") === current ? "true" : "false");
    }
  }

  function choose(choice) {
    current = valid(choice);
    store(current);
    apply(current);
    sync();
  }

  function init() {
    var groups = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < groups.length; i++) {
      groups[i].hidden = false;
      groups[i].addEventListener("click", function (ev) {
        var btn = ev.target.closest ? ev.target.closest("[data-theme-choice]") : null;
        if (btn) { choose(btn.getAttribute("data-theme-choice")); }
      });
    }
    sync();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Another tab changed the theme: follow it.
  window.addEventListener("storage", function (ev) {
    if (ev.key === KEY || ev.key === null) { current = load(); apply(current); sync(); }
  });
})();
