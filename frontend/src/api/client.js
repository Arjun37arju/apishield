const BASE_URL = "http://127.0.0.1:8000";

export async function validateTarget(url) {
  const res = await fetch(`${BASE_URL}/targets/validate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url,
      permission_confirmed: true,
    }),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.detail || "Validation failed");
  }

  return data;
}