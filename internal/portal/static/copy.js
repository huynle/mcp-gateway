// Copy buttons: progressive enhancement for <button data-copy
// data-copy-target="ID" hidden>, which copies the text of the element with
// that id (a command or token in a <pre>). Without this file the text is
// still selectable. Loaded as a same-origin script (CSP script-src 'self');
// no inline handlers.
(function () {
  "use strict";

  function init() {
    if (!navigator.clipboard || !navigator.clipboard.writeText) { return; }
    Array.prototype.forEach.call(document.querySelectorAll("[data-copy][data-copy-target]"), function (button) {
      var target = document.getElementById(button.getAttribute("data-copy-target"));
      if (!target) { return; }
      var label = button.textContent;
      button.hidden = false;
      button.addEventListener("click", function () {
        navigator.clipboard.writeText(target.textContent.trim()).then(function () {
          button.textContent = "Copied";
        }, function () {
          button.textContent = "Copy failed";
        });
        window.setTimeout(function () { button.textContent = label; }, 2000);
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
