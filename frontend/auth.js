/**
 * SkillSwap — Frontend Auth Helper
 * Drop this in any page that needs the current user or auth token.
 */

const Auth = (() => {
  const TOKEN_KEY = 'skillswap_token';
  const USER_KEY  = 'skillswap_user';

  function getToken()  { return localStorage.getItem(TOKEN_KEY); }
  function getUser()   {
    const u = localStorage.getItem(USER_KEY);
    try { return u ? JSON.parse(u) : null; } catch { return null; }
  }

  function save(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = 'login.html';
  }

  /** Redirect to login if not authenticated. Call at top of protected pages. */
  function requireAuth() {
    if (!getToken() || !getUser()) {
      window.location.href = 'login.html';
      return false;
    }
    return true;
  }

  /** Convenience fetch wrapper that adds Bearer token automatically. */
  async function apiFetch(url, options = {}) {
    const token = getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    return fetch(url, { ...options, headers });
  }

  return { getToken, getUser, save, logout, requireAuth, apiFetch };
})();