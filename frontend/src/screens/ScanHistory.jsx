import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listScans, rememberScan } from "../api/client";

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    listScans(50)
      .then((d) => setScans(Array.isArray(d) ? d : []))
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div>
      <h2>Scan History</h2>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {!error && scans.length === 0 && <p>No scans saved yet.</p>}
      {scans.length > 0 && (
        <table border="1" cellPadding="4" style={{ borderCollapse: "collapse", width: "100%" }}>
          <thead>
            <tr>
              <th>Scan</th><th>Target</th><th>State</th><th>Requests</th>
              <th>Started</th><th>Open</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td>{s.id}</td>
                <td>{s.scope}</td>
                <td>{s.state}</td>
                <td>{s.requests_made}</td>
                <td>{s.started_at || s.created_at}</td>
                <td>
                  <Link to={"/progress/" + s.id} onClick={() => rememberScan(s.id)}>progress</Link>
                  {" | "}
                  <Link to={"/findings/" + s.id} onClick={() => rememberScan(s.id)}>findings</Link>
                  {" | "}
                  <Link to={"/report/" + s.id} onClick={() => rememberScan(s.id)}>report</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}