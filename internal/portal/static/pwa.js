// Installable app: registers the service worker (/sw.js, scope "/") so
// the portal can be installed and, later, receive push notifications.
// Loaded deferred from package nav's "page.head" on every page; same-origin
// (CSP script-src 'self'), no inline handlers. Service workers need a
// secure context (HTTPS or localhost); elsewhere this does nothing.
(function () {
  "use strict";

  if (!("serviceWorker" in navigator) || !window.isSecureContext) { return; }

  // Extension point: called once with the ServiceWorkerRegistration. The
  // "notifications on this device" control (elements with data-push-*
  // attributes) hooks in here: registration.pushManager is the entry to
  // Web Push. Nothing else on the page depends on this script.
  function onRegistered(registration) {
    return registration;
  }

  navigator.serviceWorker.register("/sw.js", { scope: "/" }).then(onRegistered, function () {
    // Registration failed (private mode, blocked by policy): the portal
    // works the same without a worker.
  });
})();
