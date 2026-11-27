import { useEffect, useState } from "react";
import { listChecks, getSelectedChecks, saveSelectedChecks } from "../api/client";

export default function ScanProfile() {
  const [checks, setChecks] = useState([]);
  const [selected, setSelected] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    listChecks()
      .then((list) => {
        setChecks(list);
        const stored = getSelectedChecks();
        setSelected(stored || list.map((c) => c.id));
      })
      .catch((e) => setError(e.message));
  }, []);

  function update(ids) {
    setSelected(ids);
    // everything selected = store nothing, so new checks are included later
    saveSelectedChecks(ids.length === checks.length ? null : ids);
  }

  function toggle(id) {
    update(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);
  }

  return (
    <div style={{ maxWidth: 760 }}>
      <h2>Scan Profile</h2>
      <p>Choose which checks the next scan runs. Your choice is used by Target Setup.</p>
      {error && <p style={{ color: "red" }}>{error}</p>}

      <p>
        <button onClick={() => update(checks.map((c) => c.id))}>Select all</button>{" "}
        <button onClick={() => update([])}>Clear</button>{" "}
        {selected.length} of {checks.length} selected
      </p>
      {selected.length === 0 && checks.length > 0 && (
        <p style={{ color: "orange" }}>
          Nothing selected: the scan will run ALL checks.
        </p>
      )}

      <table border="1" cellPadding="4" style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr><th>Run</th><th>Check</th><th>What it does</th></tr>
        </thead>
        <tbody>
          {checks.map((c) => (
            <tr key={c.id}>
              <td>
                <input
                  type="checkbox"
                  checked={selected.includes(c.id)}
                  onChange={() => toggle(c.id)}
                />
              </td>
              <td>{c.name}</td>
              <td style={{ textAlign: "left" }}>{c.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p><small>
        Limits (100 requests, 2 at a time, timeouts) are enforced by the backend
        and cannot be raised here.
      </small></p>
    </div>
  );
}