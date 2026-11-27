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