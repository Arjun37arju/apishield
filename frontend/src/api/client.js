const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const res = await fetch(BASE_URL + path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(
      typeof detail === "string" ? detail : "Request failed (" + res.status + ")"
    );
  }
  return data;
}

export function validateTarget(url, permissionConfirmed = true) {
  return request("/targets/validate", {
    method: "POST",
    body: JSON.stringify({ url, permission_confirmed: permissionConfirmed }),
  });
}

export const listChecks = () => request("/checks");

export const startScan = (payload) =>
  request("/scans", { method: "POST", body: JSON.stringify(payload) });

export const getScan = (id) => request("/scans/" + id);

export const listScans = (limit = 50) => request("/scans?limit=" + limit);

export const getFindings = (id) => request("/scans/" + id + "/findings");

export const cancelScan = (id) =>
  request("/scans/" + id + "/cancel", { method: "POST" });

export const createReport = (id) =>
  request("/scans/" + id + "/report", { method: "POST" });

export const reportUrl = (fileName) => BASE_URL + "/reports/" + fileName;

export const rememberScan = (id) => {
  try { localStorage.setItem("lastScanId", id); } catch { /* ignore */ }
};
export const lastScan = () => {
  try { return localStorage.getItem("lastScanId") || ""; } catch { return ""; }
};

export const getSelectedChecks = () => {
  try {
    const raw = localStorage.getItem("selectedChecks");
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
};
export const saveSelectedChecks = (ids) => {
  try {
    if (ids === null) localStorage.removeItem("selectedChecks");
    else localStorage.setItem("selectedChecks", JSON.stringify(ids));
  } catch { /* ignore */ }
};

// Logins live in memory only. Never put them in localStorage.
let authForm = { user_a: { type: "bearer" }, user_b: { type: "bearer" } };
export const getAuthForm = () => authForm;
export const setAuthForm = (f) => { authForm = f; };

function specFrom(a) {
  if (!a) return null;
  if (a.type === "bearer" && a.token) {
    return { type: "bearer", token: a.token, expired_token: a.expired_token || "" };
  }
  if (a.type === "basic" && a.username && a.password) {
    return { type: "basic", username: a.username, password: a.password };
  }
  if (a.type === "api_key" && a.key) {
    return { type: "api_key", key: a.key, header_name: a.header_name || "X-API-Key" };
  }
  return null;
}

export function buildAuthPayload() {
  const user_a = specFrom(authForm.user_a);
  if (!user_a) return null;
  const out = { user_a };
  const user_b = specFrom(authForm.user_b);
  if (user_b) out.user_b = user_b;
  return out;
}