// Installable app and Web Push: registers the service worker (/sw.js,
// scope "/") so the portal can be installed, and drives My account's
// "notifications on this device" control (elements with data-push-*
// attributes, rendered hidden; docs/push-notifications.md).
// Loaded deferred from package nav's "page.head" on every page; same-origin
// (CSP script-src 'self'), no inline handlers, text only (textContent,
// never HTML). Service workers need a secure context (HTTPS or
// localhost); elsewhere the control says the browser is not supported.
(function () {
  "use strict";

  var control = document.querySelector("[data-push-control]");

  // The CSRF token the portal puts on <body hx-headers='{"X-CSRF-Token": …}'>
  // for htmx; fetch() sends it the same way.
  function csrfToken() {
    try {
      var headers = JSON.parse(document.body.getAttribute("hx-headers") || "{}");
      return headers["X-CSRF-Token"] || "";
    } catch (e) {
      return "";
    }
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrfToken() },
      body: JSON.stringify(body || {})
    });
  }

  // errorText reads {"error": "..."} from a failed response.
  function errorText(res, fallback) {
    return res.json().then(function (body) {
      return (body && typeof body.error === "string" && body.error) || fallback;
    }, function () { return fallback; });
  }

  // keyBytes turns the base64url applicationServerKey into bytes.
  function keyBytes(b64) {
    var s = String(b64).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) { s += "="; }
    var raw = window.atob(s);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) { out[i] = raw.charCodeAt(i); }
    return out;
  }

  // part finds one of the control's elements by its full selector.
  function part(selector) { return control.querySelector(selector); }

  function setState(text, tone) {
    var state = part("[data-push-state]");
    if (state) {
      state.textContent = text;
      state.className = "pill " + tone;
    }
  }

  function say(text) {
    var message = part("[data-push-message]");
    if (message) { message.textContent = text || ""; }
  }

  // unsupported reveals the control with the reason and nothing to press.
  function unsupported() {
    if (!control) { return; }
    control.hidden = false;
    setState("Not supported on this browser", "none");
    var toggle = part("[data-push-toggle]");
    if (toggle) { toggle.disabled = true; }
    var test = part("[data-push-test]");
    if (test) { test.hidden = true; }
  }

  function pushControl(registration) {
    var toggle = part("[data-push-toggle]");
    var test = part("[data-push-test]");
    if (!toggle || !test) { return; }
    control.hidden = false;
    if (!("PushManager" in window) || !("Notification" in window) || !registration.pushManager) {
      unsupported();
      return;
    }
    var current = null;
    var busy = false;

    function render() {
      toggle.disabled = busy;
      test.disabled = busy;
      if (Notification.permission === "denied") {
        setState("Blocked in browser settings", "blocked");
        toggle.textContent = "Turn on for this device";
        toggle.disabled = true;
        test.hidden = true;
        return;
      }
      if (current) {
        setState("On for this device", "active");
        toggle.textContent = "Turn off for this device";
        test.hidden = false;
      } else {
        setState("Off", "none");
        toggle.textContent = "Turn on for this device";
        test.hidden = true;
      }
    }

    function finish(text) {
      busy = false;
      say(text);
      render();
    }

    function turnOn() {
      // The permission prompt is requested synchronously from the click:
      // iOS (and Safari generally) refuses it after an await. Old Safari
      // takes a callback and returns undefined; Notification.permission
      // then has the answer.
      var asked = Notification.requestPermission();
      Promise.resolve(asked).then(function (permission) {
        permission = permission || Notification.permission;
        if (permission !== "granted") {
          throw new Error(permission === "denied"
            ? "Notifications are blocked for this site in the browser settings."
            : "Notifications were not allowed.");
        }
        return fetch("/account/push/key", { credentials: "same-origin", headers: { "Accept": "application/json" } });
      }).then(function (res) {
        if (!res.ok) {
          return errorText(res, "Notifications are not available right now.").then(function (t) { throw new Error(t); });
        }
        return res.json();
      }).then(function (body) {
        return registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(body.publicKey) });
      }).then(function (subscription) {
        return post("/account/push/subscribe", subscription.toJSON()).then(function (res) {
          if (res.ok) {
            current = subscription;
            return;
          }
          // The gateway refused it: do not leave a browser subscription
          // behind that nothing sends to.
          return errorText(res, "The subscription could not be saved.").then(function (t) {
            return subscription.unsubscribe().then(function () { throw new Error(t); }, function () { throw new Error(t); });
          });
        });
      }).then(function () {
        finish("Notifications are on for this device.");
      }, function (err) {
        finish((err && err.message) || "Notifications could not be turned on.");
      });
    }

    function turnOff() {
      var subscription = current;
      var endpoint = subscription.endpoint;
      subscription.unsubscribe().then(function () {
        current = null;
        return post("/account/push/unsubscribe", { endpoint: endpoint });
      }).then(function (res) {
        finish(res.ok ? "Notifications are off for this device." : "Turned off here; reload to check the device list.");
      }, function () {
        finish("Notifications could not be turned off.");
      });
    }

    toggle.addEventListener("click", function () {
      if (busy) { return; }
      busy = true;
      say("");
      render();
      if (current) { turnOff(); } else { turnOn(); }
    });

    test.addEventListener("click", function () {
      if (busy) { return; }
      busy = true;
      render();
      post("/account/push/test", {}).then(function (res) {
        if (!res.ok) {
          return errorText(res, "The test notification could not be sent.");
        }
        return res.json().then(function (body) {
          var n = (body && body.sent) || 0;
          if (n === 0) { return "No device got it. Turn notifications off and on again on this device."; }
          return "Sent to " + n + (n === 1 ? " device." : " devices.");
        });
      }).then(finish, function () {
        finish("The test notification could not be sent.");
      });
    });

    registration.pushManager.getSubscription().then(function (subscription) {
      current = subscription;
      render();
    }, function () { render(); });
  }

  if (!("serviceWorker" in navigator) || !window.isSecureContext) {
    unsupported();
    return;
  }

  // Called once with the ServiceWorkerRegistration: the push control
  // hooks in here (registration.pushManager is the entry to Web Push).
  function onRegistered(registration) {
    if (control) { pushControl(registration); }
    return registration;
  }

  navigator.serviceWorker.register("/sw.js", { scope: "/" }).then(onRegistered, function () {
    // Registration failed (private mode, blocked by policy): the portal
    // works the same without a worker; only the push control cannot.
    unsupported();
  });
})();
