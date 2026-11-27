import { useState } from "react";
import { getAuthForm, setAuthForm } from "../api/client";

function AccountForm({ title, value, onChange, showExpired }) {
  const set = (k, v) => onChange({ ...value, [k]: v });
  return (
    <fieldset style={{ marginBottom: 16 }}>
      <legend>{title}</legend>
      <label>
        Login type{" "}
        <select value={value.type} onChange={(e) => onChange({ type: e.target.value })}>
          <option value="bearer">Bearer / JWT token</option>
          <option value="basic">Basic (username + password)</option>
          <option value="api_key">API key</option>
        </select>
      </label>

      {value.type === "bearer" && (
        <>
          <p>
            <input type="password" placeholder="Token" autoComplete="off"
              style={{ width: "100%" }} value={value.token || ""}
              onChange={(e) => set("token", e.target.value)} />
          </p>
          {showExpired && (
            <p>
              <input type="password" placeholder="Expired token (optional, for the expired-token check)"
                autoComplete="off" style={{ width: "100%" }}
                value={value.expired_token || ""}
                onChange={(e) => set("expired_token", e.target.value)} />
            </p>
          )}
        </>
      )}
      {value.type === "basic" && (
        <p>
          <input type="text" placeholder="Username" autoComplete="off"
            value={value.username || ""} onChange={(e) => set("username", e.target.value)} />{" "}
          <input type="password" placeholder="Password" autoComplete="off"
            value={value.password || ""} onChange={(e) => set("password", e.target.value)} />
        </p>
      )}
      {value.type === "api_key" && (
        <p>
          <input type="text" placeholder="Header name" autoComplete="off"
            value={value.header_name || "X-API-Key"}
            onChange={(e) => set("header_name", e.target.value)} />{" "}
          <input type="password" placeholder="API key" autoComplete="off"
            value={value.key || ""} onChange={(e) => set("key", e.target.value)} />
        </p>
      )}
    </fieldset>
  );
}

export default function AuthSettings() {
  const [form, setForm] = useState(getAuthForm());
  const [saved, setSaved] = useState(false);

  function update(next) {
    setForm(next);
    setAuthForm(next);
    setSaved(true);
  }

  function clearAll() {
    update({ user_a: { type: "bearer" }, user_b: { type: "bearer" } });
    setSaved(false);
  }

  return (
    <div style={{ maxWidth: 640 }}>
      <h2>Authentication Settings</h2>
      <p>
        Use TEST accounts only. Logins are kept in this browser tab's memory and
        sent to your local backend when you start a scan. They are never stored
        and disappear when you refresh the page.
      </p>
      <AccountForm title="User A (main test user)" value={form.user_a}
        onChange={(v) => update({ ...form, user_a: v })} showExpired />
      <AccountForm title="User B (second user, for BOLA / IDOR checks)" value={form.user_b}
        onChange={(v) => update({ ...form, user_b: v })} />
      <button onClick={clearAll}>Clear logins</button>
      {saved && <p><small>Kept in memory for the next scan.</small></p>}
    </div>
  );
}