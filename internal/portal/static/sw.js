// MCP Gateway service worker (installable app, push notifications).
//
// Served by the portal at /sw.js (scope "/"), never from /static/: the
// portal replaces the three placeholder values below with the versioned
// asset URLs of this build, a hash of them, and the notification icon
// (package portal, pwa.go). The served file is byte-identical for a given
// build, so browsers reinstall the worker exactly when a deploy changes it.
//
// Caching rules (docs/portal-ui.md, "Installable app (PWA)"):
//   - install: precache only the static assets (their ?v= URLs) and the
//     anonymous /offline page;
//   - navigations: network only; when the network fails, the cached
//     /offline page. Page HTML (signed in or not) is never stored;
//   - same-origin GET /static/...: cache first (the URLs are versioned);
//   - everything else (POST, htmx, /mcp, other origins): not intercepted.
(function () {
  "use strict";

  var CACHE_VERSION = "__CACHE_VERSION__";
  var PRECACHE_URLS = ["__PRECACHE_URLS__"];
  var ICON_URL = "__ICON_URL__";
  var CACHE = "mcp-gateway-static-" + CACHE_VERSION;
  var OFFLINE_URL = "/offline";
  var DEFAULT_URL = "/approvals";

  self.addEventListener("install", function (event) {
    event.waitUntil(caches.open(CACHE).then(function (cache) {
      // credentials "omit": the offline page is cached as the anonymous
      // copy (the portal renders it anonymously anyway).
      return cache.addAll(PRECACHE_URLS.map(function (url) {
        return new Request(url, { credentials: "omit", cache: "reload" });
      }));
    }).then(function () { return self.skipWaiting(); }));
  });

  self.addEventListener("activate", function (event) {
    event.waitUntil(caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (key) {
        return key.indexOf("mcp-gateway-") === 0 && key !== CACHE;
      }).map(function (key) { return caches.delete(key); }));
    }).then(function () { return self.clients.claim(); }));
  });

  self.addEventListener("fetch", function (event) {
    var request = event.request;
    if (request.method !== "GET") { return; }
    if (request.mode === "navigate") {
      event.respondWith(handleNavigation(request));
      return;
    }
    var url = new URL(request.url);
    if (url.origin === self.location.origin && url.pathname.indexOf("/static/") === 0) {
      event.respondWith(handleStatic(request));
    }
    // Anything else falls through to the network untouched.
  });

  // Network only; the offline page when the network is unreachable.
  function handleNavigation(request) {
    return fetch(request).catch(function () {
      return caches.match(OFFLINE_URL).then(function (offline) {
        return offline || Response.error();
      });
    });
  }

  // Cache first: /static/ URLs carry a content hash, so a cached copy is
  // never stale. A miss is fetched and stored if it is a plain 200.
  function handleStatic(request) {
    return caches.open(CACHE).then(function (cache) {
      return cache.match(request).then(function (hit) {
        if (hit) { return hit; }
        return fetch(request).then(function (response) {
          if (response.ok && response.type === "basic") {
            cache.put(request, response.clone());
          }
          return response;
        });
      });
    });
  }

  // safePath returns url if it is a same-origin path ("/..."), else the
  // approvals page: a push payload can never send the user elsewhere.
  function safePath(url) {
    if (typeof url !== "string" || url.charAt(0) !== "/" || url.charAt(1) === "/" || url.charAt(1) === "\\") {
      return DEFAULT_URL;
    }
    try {
      var parsed = new URL(url, self.location.origin);
      if (parsed.origin !== self.location.origin) { return DEFAULT_URL; }
      return parsed.pathname + parsed.search + parsed.hash;
    } catch (e) {
      return DEFAULT_URL;
    }
  }

  self.addEventListener("push", function (event) {
    var msg = null;
    try { msg = event.data ? event.data.json() : null; } catch (e) { msg = null; }
    var title = "MCP Gateway";
    var options = { body: "Something needs your attention", icon: ICON_URL, badge: ICON_URL, data: { url: DEFAULT_URL } };
    if (msg && typeof msg === "object" && typeof msg.title === "string" && msg.title) {
      title = msg.title;
      options.body = typeof msg.body === "string" ? msg.body : "";
      options.data.url = safePath(msg.url);
      if (typeof msg.tag === "string" && msg.tag) {
        options.tag = msg.tag;
        options.renotify = true;
      }
    }
    event.waitUntil(self.registration.showNotification(title, options));
  });

  self.addEventListener("notificationclick", function (event) {
    event.notification.close();
    var target = safePath(event.notification.data && event.notification.data.url);
    var absolute = new URL(target, self.location.origin).href;
    event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (windows) {
      var same = windows.filter(function (c) { return new URL(c.url).origin === self.location.origin; });
      for (var i = 0; i < same.length; i++) {
        if (same[i].url === absolute) { return same[i].focus(); }
      }
      if (same.length > 0) {
        return same[0].focus().then(function (client) {
          return client.navigate(absolute);
        }).catch(function () {
          return self.clients.openWindow(target);
        });
      }
      return self.clients.openWindow(target);
    }));
  });
})();
