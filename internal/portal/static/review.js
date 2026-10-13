// Tool review pages (/servers/{id}/review, /admin/servers/{id}/review):
// progressive enhancement of the server-rendered form. Without this file
// the checkboxes (tools, resources, templates, prompts), "Approve" and
// "Approve with all tools enabled" still work; with it: Select all / none / read-only, group checkboxes, a live
// "N of M selected" count and a filter box. Loaded as a same-origin
// script (CSP script-src 'self'); no inline handlers.
(function () {
  "use strict";

  function each(list, fn) { Array.prototype.forEach.call(list, fn); }

  function init(form) {
    var rows = form.querySelectorAll("[data-tool]");
    var groups = form.querySelectorAll("[data-group]");
    var count = form.querySelector("[data-review-count]");
    var filter = form.querySelector("[data-review-filter]");
    var needsSelection = form.querySelectorAll("[data-requires-selection]");

    each(form.querySelectorAll("[data-js]"), function (el) { el.hidden = false; });

    // The row's own checkbox: name="enable" for tools, enable_resource /
    // enable_template / enable_prompt for resources, templates, prompts.
    function box(row) { return row.querySelector('.tool-pick input[type="checkbox"]'); }
    function visible(row) { return !row.hidden; }

    function update() {
      var on = 0;
      each(rows, function (row) { if (box(row).checked) { on++; } });
      if (count) { count.textContent = on + " of " + rows.length + " selected"; }
      each(needsSelection, function (button) {
        button.disabled = on === 0;
        button.setAttribute("aria-disabled", on === 0 ? "true" : "false");
        button.title = on === 0 ? "Select at least one capability first" : "";
      });
      each(groups, function (g) {
        var n = 0, total = 0;
        each(g.querySelectorAll("[data-tool]"), function (row) {
          total++;
          if (box(row).checked) { n++; }
        });
        var c = g.querySelector("[data-group-count]");
        if (c) { c.textContent = n + "/" + total; }
        var gc = g.querySelector("[data-group-check]");
        if (gc) {
          gc.checked = total > 0 && n === total;
          gc.indeterminate = n > 0 && n < total;
        }
      });
    }

    // Select all / none / read-only act on the rows the filter shows.
    each(form.querySelectorAll("[data-select]"), function (btn) {
      btn.addEventListener("click", function () {
        var mode = btn.getAttribute("data-select");
        each(rows, function (row) {
          if (!visible(row)) { return; }
          // "Select read-only" picks among tools; it leaves resources,
          // templates and prompts (data-item) as they are.
          if (mode === "read" && row.hasAttribute("data-item")) { return; }
          box(row).checked = mode === "all" || (mode === "read" && row.getAttribute("data-kind") === "read");
        });
        update();
      });
    });

    each(groups, function (g) {
      var gc = g.querySelector("[data-group-check]");
      if (!gc) { return; }
      // A click on the checkbox must not toggle the <details>.
      gc.addEventListener("click", function (ev) { ev.stopPropagation(); });
      gc.addEventListener("change", function () {
        each(g.querySelectorAll("[data-tool]"), function (row) {
          if (visible(row)) { box(row).checked = gc.checked; }
        });
        update();
      });
    });

    // The kind override changes what "Select read-only" picks.
    each(rows, function (row) {
      var sel = row.querySelector("select");
      if (!sel) { return; }
      sel.addEventListener("change", function () {
        row.setAttribute("data-kind", sel.value || row.getAttribute("data-hint"));
      });
    });

    form.addEventListener("change", function (ev) {
      if (ev.target && /^enable(_resource|_template|_prompt)?$/.test(ev.target.name)) { update(); }
    });

    if (filter) {
      filter.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") { ev.preventDefault(); }
      });
      filter.addEventListener("input", function () {
        var q = filter.value.trim().toLowerCase();
        each(groups, function (g) {
          var shown = 0;
          each(g.querySelectorAll("[data-tool]"), function (row) {
            var text = (row.getAttribute("data-name") + " " + row.textContent).toLowerCase();
            row.hidden = q !== "" && text.indexOf(q) < 0;
            if (!row.hidden) { shown++; }
          });
          g.hidden = shown === 0;
          if (q !== "" && shown > 0) { g.open = true; }
        });
      });
    }

    update();
  }

  function start() { each(document.querySelectorAll("form[data-review]"), init); }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
