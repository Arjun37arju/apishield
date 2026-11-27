import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { validateTarget, startScan, rememberScan } from "../api/client";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

// One endpoint per line:  /api/x   or   METHOD /path   or   GET /api/search q
function parseEndpoints(text) {
  const out = [];
  for (const raw of text.split("\n")) {
    const parts = raw.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) continue;
    if (METHODS.includes(parts[0].toUpperCase()) && parts[1]) {
      const item = { method: parts[0].toUpperCase(), path: parts[1] };
      if (parts.length > 2) item.params = parts.slice(2);
      out.push(item);
    } else {
      out.push(parts[0]);
    }
  }
  return out;
}

export default function TargetSetup() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [permission, setPermission] = useState(false);
  const [endpointsText, setEndpointsText] = useState("");
  const [labAccounts, setLabAccounts] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleValidate() {
    setError("");
    setResult(null);
    try {
      setResult(await validateTarget(url, permission));
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleStart(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const endpoints = parseEndpoints(endpointsText);
      const payload = {
        url,
        permission_confirmed: permission,
        lab_accounts: labAccounts,
      };
      if (endpoints.length) payload.endpoints = endpoints;
      const scan = await startScan(payload);
      rememberScan(scan.id);
      navigate("/progress/" + scan.id);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 640 }}>
      <h2>Target Setup</h2>

      <form onSubmit={handleStart}>
        <label>
          API address
          <br />
          <input
            type="text"
            placeholder="http://127.0.0.1:5000"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{ width: "100%" }}
          />
        </label>

        <p>
          <label>
            Endpoints to test (one per line, optional)
            <br />
            <textarea
              rows={7}
              style={{ width: "100%", fontFamily: "monospace" }}
              placeholder={"/api/users/me\nGET /api/search q\n/api/orders/{id}\nPATCH /api/orders/{id}\nPOST /api/login"}
              value={endpointsText}
              onChange={(e) => setEndpointsText(e.target.value)}
            />
          </label>
          <small>
            Order matters: the first few endpoints are used by the config, input
            and rate checks. Use {"{id}"} for object paths.
          </small>
        </p>

        <p>
          <label>
            <input
              type="checkbox"
              checked={labAccounts}
              onChange={(e) => setLabAccounts(e.target.checked)}
            />{" "}
            Use the built-in fake lab accounts (lab on port 5000 only)
          </label>
        </p>

        <p>
          <label>
            <input
              type="checkbox"
              checked={permission}
              onChange={(e) => setPermission(e.target.checked)}
            />{" "}
            I own this system or have written permission to test it
          </label>
        </p>

        <button type="button" onClick={handleValidate} disabled={!url || !permission}>
          Validate target
        </button>{" "}
        <button type="submit" disabled={!url || !permission || busy}>
          {busy ? "Starting..." : "Start scan"}
        </button>
      </form>

      {error && <p style={{ color: "red" }}>{error}</p>}
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
}