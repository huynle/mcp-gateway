// Insights charts (package insights, decision 3yq9s5ev).
//
// Loaded deferred, after the vendored chart.umd.min.js, on the pages that
// render the "insights.charts" template (/activity, /operations,
// /admin/insights). Same-origin, so CSP script-src 'self' allows it;
// nothing is inline. The server renders the charts as JSON in
// <script type="application/json" data-insights> (an inert data block)
// and one <canvas id="chart-<id>"> per chart; this script draws them.
//
// Colours come from the portal palette (custom properties in portal.css),
// and the charts are redrawn when the theme changes. Time buckets arrive
// as UTC milliseconds and are labelled in the browser's time zone; the
// punch card folds hourly totals into local weekday × hour. A chart with
// a drill spec is clickable: it opens the filtered table (same origin)
// for the clicked tool, user, outcome, decision or time bucket.
(function () {
  "use strict";

  var blocks = document.querySelectorAll("script[data-insights]");
  if (!blocks.length || typeof window.Chart === "undefined") { return; }
  var Chart = window.Chart;

  var specs = [];
  blocks.forEach(function (b) {
    try { specs = specs.concat(JSON.parse(b.textContent) || []); } catch (e) { /* malformed block: draw nothing for it */ }
  });

  var WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  var HOUR = 3600 * 1000;
  var DAY = 24 * HOUR;

  function palette() {
    var cs = getComputedStyle(document.documentElement);
    var get = function (n) { return cs.getPropertyValue("--" + n).trim(); };
    return {
      fg: get("fg"), muted: get("muted"), line: get("line"), panel: get("panel"),
      ok: get("ok"), danger: get("danger"), warn: get("warn"), accent: get("accent"),
      c1: get("chart-1"), c2: get("chart-2"), c3: get("chart-3"),
      c4: get("chart-4"), c5: get("chart-5"), c6: get("chart-6")
    };
  }

  function colour(p, tone) { return p[tone] || p.muted; }

  // alpha turns #rrggbb into rgba() with opacity a.
  function alpha(hex, a) {
    var m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || "");
    if (!m) { return hex; }
    return "rgba(" + parseInt(m[1], 16) + "," + parseInt(m[2], 16) + "," + parseInt(m[3], 16) + "," + a + ")";
  }

  var nf = new Intl.NumberFormat();

  function fmtValue(v, unit) {
    if (v === null || v === undefined || isNaN(v)) { return "–"; }
    if (unit === "ms") {
      if (v < 1000) { return Math.round(v) + " ms"; }
      if (v < 60000) { return (v / 1000).toFixed(1) + " s"; }
      return (v / 60000).toFixed(1) + " min";
    }
    return nf.format(v);
  }

  function withUnit(v, unit) {
    if (unit === "ms") { return fmtValue(v, unit); }
    return fmtValue(v, unit) + (unit && unit !== "count" ? " " + unit : "");
  }

  var two = function (n) { return (n < 10 ? "0" : "") + n; };

  // fmtBucket labels a bucket start in local time: hours for sub-day
  // buckets, dates for days.
  function fmtBucket(ms, bucketMs, long) {
    var d = new Date(ms);
    var date = d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    if (bucketMs >= DAY) { return long ? d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }) : date; }
    var time = two(d.getHours()) + ":" + two(d.getMinutes());
    if (long) {
      var end = new Date(ms + bucketMs);
      return date + " " + time + "–" + two(end.getHours()) + ":" + two(end.getMinutes());
    }
    return bucketMs < 6 * HOUR && d.getHours() !== 0 ? time : date + " " + time;
  }

  function truncate(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function isoSeconds(ms) { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z"); }

  // drillURL is the same-origin URL a click opens, or "" when the chart
  // has no drill spec or the click carries nothing to filter by.
  function drillURL(spec, index, seriesIndex) {
    var d = spec.drill;
    if (!d) { return ""; }
    var u = new URL(d.href, window.location.origin);
    if (u.origin !== window.location.origin) { return ""; }
    var set = false;
    if (d.param) {
      var key = spec.keys && spec.keys[index] !== undefined ? spec.keys[index] : (spec.labels || [])[index];
      if (key === undefined || key === "") { return ""; }
      u.searchParams.set(d.param, key);
      set = true;
    }
    if (d.seriesParam && spec.series[seriesIndex] && spec.series[seriesIndex].key) {
      u.searchParams.set(d.seriesParam, spec.series[seriesIndex].key);
      set = true;
    }
    if (d.time && spec.times && spec.times[index] !== undefined) {
      u.searchParams.set("since", isoSeconds(spec.times[index]));
      u.searchParams.set("until", isoSeconds(spec.times[index] + spec.bucketMs));
      set = true;
    }
    return set ? u.pathname + u.search : "";
  }

  function hit(chart, evt) {
    var els = chart.getElementsAtEventForMode(evt, "nearest", { intersect: true }, false);
    return els.length ? els[0] : null;
  }

  // interactive wires hover cursor and click-to-drill. pick maps a hit
  // element to [label index, series index].
  function interactive(spec, opts, pick) {
    if (!spec.drill) { return; }
    pick = pick || function (el) { return [el.index, el.datasetIndex]; };
    opts.onHover = function (evt, _els, chart) {
      var el = hit(chart, evt);
      var ok = el && drillURL.apply(null, [spec].concat(pick(el, chart)));
      chart.canvas.style.cursor = ok ? "pointer" : "default";
    };
    opts.onClick = function (evt, _els, chart) {
      var el = hit(chart, evt);
      if (!el) { return; }
      var url = drillURL.apply(null, [spec].concat(pick(el, chart)));
      if (url) { window.location.assign(url); }
    };
  }

  function baseOptions(spec, p) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 250 },
      plugins: {
        legend: { display: spec.series.length > 1, position: "bottom", labels: { boxWidth: 10, boxHeight: 10, usePointStyle: true } },
        tooltip: {
          backgroundColor: p.panel, titleColor: p.fg, bodyColor: p.fg, footerColor: p.muted,
          borderColor: p.line, borderWidth: 1, padding: 10, boxPadding: 4
        }
      }
    };
  }

  function timeLabels(spec) {
    return spec.times.map(function (t) { return fmtBucket(t, spec.bucketMs, false); });
  }

  function timeTitle(spec) {
    return function (items) { return items.length ? fmtBucket(spec.times[items[0].dataIndex], spec.bucketMs, true) : ""; };
  }

  function valueLabel(spec) {
    return function (item) { return " " + item.dataset.label + ": " + withUnit(item.raw, spec.unit); };
  }

  function valueAxis(spec, p, extra) {
    var a = { beginAtZero: true, grid: { color: p.line }, border: { display: false },
      ticks: { precision: 0, callback: function (v) { return fmtValue(v, spec.unit); } } };
    for (var k in extra) { a[k] = extra[k]; }
    return a;
  }

  var builders = {
    stacked: function (spec, p) {
      var o = baseOptions(spec, p);
      o.interaction = { mode: "index", intersect: false };
      o.plugins.tooltip.callbacks = {
        title: timeTitle(spec), label: valueLabel(spec),
        footer: function (items) {
          var sum = items.reduce(function (s, i) { return s + (i.raw || 0); }, 0);
          return "Total: " + withUnit(sum, spec.unit);
        }
      };
      o.scales = { x: { stacked: true, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } }, y: valueAxis(spec, p, { stacked: true }) };
      interactive(spec, o);
      // A stacked click with intersect:false would pick the nearest bar of
      // any series; the hit test above uses intersect:true so the clicked
      // segment decides the series.
      return { type: "bar", data: { labels: timeLabels(spec), datasets: spec.series.map(function (s) {
        return { label: s.name, data: s.data, backgroundColor: colour(p, s.tone), stack: "s", borderRadius: 2, maxBarThickness: 28 };
      }) }, options: o };
    },

    line: function (spec, p) {
      var o = baseOptions(spec, p);
      o.interaction = { mode: "index", intersect: false };
      o.plugins.tooltip.callbacks = { title: timeTitle(spec), label: valueLabel(spec) };
      o.scales = { x: { grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } }, y: valueAxis(spec, p) };
      return { type: "line", data: { labels: timeLabels(spec), datasets: spec.series.map(function (s, i) {
        var c = colour(p, s.tone);
        return { label: s.name, data: s.data, borderColor: c, backgroundColor: alpha(c, 0.12), fill: i === 0 && spec.series.length === 1,
          spanGaps: false, tension: 0.25, pointRadius: spec.times.length > 60 ? 0 : 2, pointHoverRadius: 4, borderWidth: 2 };
      }) }, options: o };
    },

    bar: function (spec, p) {
      var o = baseOptions(spec, p);
      o.plugins.tooltip.callbacks = { label: valueLabel(spec) };
      o.scales = { x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: false } }, y: valueAxis(spec, p) };
      interactive(spec, o);
      return { type: "bar", data: { labels: spec.labels, datasets: spec.series.map(function (s) {
        return { label: s.name, data: s.data, backgroundColor: colour(p, s.tone), borderRadius: 3 };
      }) }, options: o };
    },

    hbar: function (spec, p) {
      var o = baseOptions(spec, p);
      var many = spec.series.length > 1;
      o.indexAxis = "y";
      o.interaction = { mode: "nearest", axis: "y", intersect: false };
      o.plugins.tooltip.callbacks = {
        title: function (items) { return items.length ? spec.labels[items[0].dataIndex] : ""; },
        label: valueLabel(spec)
      };
      if (many) {
        o.interaction = { mode: "index", axis: "y", intersect: false };
        o.plugins.tooltip.callbacks.footer = function (items) {
          return "Total: " + withUnit(items.reduce(function (s, i) { return s + (i.raw || 0); }, 0), spec.unit);
        };
      }
      o.scales = {
        x: valueAxis(spec, p, { stacked: many }),
        y: { stacked: many, grid: { display: false }, ticks: { autoSkip: false, callback: function (v) { return truncate(spec.labels[v], 28); } } }
      };
      // Any part of a row (a tool, a user) drills into that row.
      interactive(spec, o, function (el) { return [el.index, el.datasetIndex]; });
      return { type: "bar", data: { labels: spec.labels, datasets: spec.series.map(function (s) {
        return { label: s.name, data: s.data, backgroundColor: colour(p, s.tone), stack: "s", borderRadius: 2, maxBarThickness: 18 };
      }) }, options: o };
    },

    doughnut: function (spec, p) {
      var o = baseOptions(spec, p);
      var s = spec.series[0] || { data: [], tone: "" };
      var tones = String(s.tone || "").split(",");
      var total = (s.data || []).reduce(function (a, b) { return a + (b || 0); }, 0);
      o.cutout = "62%";
      o.plugins.legend = { display: true, position: "right", labels: { boxWidth: 10, boxHeight: 10, usePointStyle: true } };
      o.plugins.tooltip.callbacks = { label: function (item) {
        var pct = total ? " (" + (item.raw * 100 / total).toFixed(1) + "%)" : "";
        return " " + item.label + ": " + withUnit(item.raw, spec.unit) + pct;
      } };
      interactive(spec, o, function (el) { return [el.index, 0]; });
      return { type: "doughnut", data: { labels: spec.labels || [], datasets: [{ data: s.data || [],
        backgroundColor: tones.map(function (t) { return colour(p, t); }), borderColor: p.panel, borderWidth: 2, hoverOffset: 6 }] }, options: o };
    },

    punchcard: function (spec, p) {
      // Fold the hourly totals into local weekday (Mon..Sun) × hour.
      var grid = {}, max = 0;
      (spec.series[0] ? spec.series[0].data : []).forEach(function (v, i) {
        if (!v) { return; }
        var d = new Date(spec.times[i]);
        var key = ((d.getDay() + 6) % 7) + ":" + d.getHours();
        grid[key] = (grid[key] || 0) + v;
        max = Math.max(max, grid[key]);
      });
      var pts = Object.keys(grid).map(function (k) {
        var parts = k.split(":"), v = grid[k];
        return { x: +parts[1], y: 6 - parts[0], v: v, r: 3 + 13 * Math.sqrt(v / max) };
      });
      var c = colour(p, "accent");
      var o = baseOptions(spec, p);
      o.plugins.legend = { display: false };
      o.plugins.tooltip.callbacks = { title: function () { return ""; }, label: function (item) {
        var r = item.raw;
        return " " + WEEKDAYS[6 - r.y] + " " + two(r.x) + ":00–" + two((r.x + 1) % 24) + ":00: " + withUnit(r.v, spec.unit);
      } };
      o.scales = {
        x: { type: "linear", min: -0.5, max: 23.5, grid: { color: p.line }, ticks: { stepSize: 1, autoSkip: true, maxRotation: 0, callback: function (v) { return v % 3 === 0 ? two(v) + ":00" : ""; } } },
        y: { type: "linear", min: -0.5, max: 6.5, grid: { color: p.line }, ticks: { stepSize: 1, callback: function (v) { return WEEKDAYS[6 - v] || ""; } } }
      };
      return { type: "bubble", data: { datasets: [{ label: "calls", data: pts, backgroundColor: alpha(c, 0.55), borderColor: c, borderWidth: 1 }] }, options: o };
    },

    matrix: function (spec, p) {
      var max = (spec.points || []).reduce(function (m, pt) { return Math.max(m, pt.v); }, 0) || 1;
      var rows = spec.labels.length;
      var pts = (spec.points || []).map(function (pt) {
        return { x: pt.x, y: rows - 1 - pt.y, row: pt.y, v: pt.v, r: 3 + 14 * Math.sqrt(pt.v / max) };
      });
      var c = colour(p, "accent");
      var o = baseOptions(spec, p);
      o.plugins.legend = { display: false };
      o.plugins.tooltip.callbacks = { title: function () { return ""; }, label: function (item) {
        var r = item.raw;
        return " " + spec.labels[r.row] + " · " + spec.xLabels[r.x] + ": " + withUnit(r.v, spec.unit);
      } };
      o.scales = {
        x: { type: "linear", min: -0.5, max: spec.xLabels.length - 0.5, grid: { color: p.line },
          ticks: { stepSize: 1, autoSkip: false, maxRotation: 35, minRotation: 0, callback: function (v) { return truncate(spec.xLabels[v] || "", 24); } } },
        y: { type: "linear", min: -0.5, max: rows - 0.5, grid: { color: p.line },
          ticks: { stepSize: 1, autoSkip: false, callback: function (v) { return truncate(spec.labels[rows - 1 - v] || "", 22); } } }
      };
      interactive(spec, o, function (el, chart) {
        return [chart.data.datasets[el.datasetIndex].data[el.index].row, 0];
      });
      return { type: "bubble", data: { datasets: [{ label: "calls", data: pts, backgroundColor: alpha(c, 0.55), borderColor: c, borderWidth: 1 }] }, options: o };
    }
  };

  var drawn = [];

  function draw() {
    drawn.forEach(function (c) { c.destroy(); });
    drawn = [];
    var p = palette();
    Chart.defaults.color = p.muted;
    Chart.defaults.borderColor = p.line;
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    specs.forEach(function (spec) {
      var canvas = document.getElementById("chart-" + spec.id);
      var build = builders[spec.kind];
      if (!canvas || !build || !spec.series) { return; }
      try { drawn.push(new Chart(canvas, build(spec, p))); } catch (e) { /* one bad chart must not stop the rest */ }
    });
  }

  draw();

  // Redraw with the new palette when the theme toggle (theme.js) or the
  // system preference changes.
  var pending = 0;
  function redraw() { window.clearTimeout(pending); pending = window.setTimeout(draw, 30); }
  new MutationObserver(redraw).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (mq.addEventListener) { mq.addEventListener("change", redraw); }
  }
})();
