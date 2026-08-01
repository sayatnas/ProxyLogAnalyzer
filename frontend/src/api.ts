// One place that knows the backend's address and how to attach the token.
// Components call these instead of using fetch directly.

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:5000";

const TOKEN_KEY = "token";

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t: string) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

export class AuthError extends Error {}

/** Attach the bearer token, and turn a 401 into a typed error the app can react to. */
export async function authedFetch(path: string, options: RequestInit = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: { ...options.headers, Authorization: `Bearer ${getToken()}` },
  });
  if (response.status === 401) {
    clearToken();
    throw new AuthError("session expired");
  }
  return response;
}

export async function login(username: string, password: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) {
    let message = response.statusText;
    try {
      const body = await response.json();
      if (body.error) message = body.error;
    } catch {
      // non-JSON error body; keep the status text
    }
    throw new Error(message);
  }
  const data = await response.json();
  return data.token;
}
