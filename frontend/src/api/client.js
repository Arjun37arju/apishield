const BASE_URL = import.meta.env.VITE_API_BASE_URL;

export async function getHealth() {
  const res = await fetch(`${BASE_URL}/health`);
  if (!res.ok) throw new Error("Backend not reachable");
  return res.json();
}
