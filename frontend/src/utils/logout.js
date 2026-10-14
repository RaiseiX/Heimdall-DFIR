const LOGOUT_TIMEOUT_MS = 3000;

export async function performLogout({ logout, exit, getRefreshToken, timeoutMs = LOGOUT_TIMEOUT_MS }) {
  const refreshToken = getRefreshToken();
  if (refreshToken) {
    let timer;
    const limit = new Promise((resolve) => { timer = setTimeout(resolve, timeoutMs); });
    try {
      await Promise.race([Promise.resolve().then(() => logout(refreshToken)).catch(() => {}), limit]);
    } finally {
      clearTimeout(timer);
    }
  }
  exit.end();
}
