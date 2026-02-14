/* API helpers extracted from dashboard monolith. */

function getCsrfToken() {
        var match = document.cookie.match(/trueid_csrf_token=([^;]+)/);
        return match ? match[1] : '';
      }

      function mutHeaders() {
        return {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken()
        };
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.getCsrfToken === 'function') window.TrueID.getCsrfToken = window.getCsrfToken;
  if (typeof window.mutHeaders === 'function') window.TrueID.mutHeaders = window.mutHeaders;
})();
