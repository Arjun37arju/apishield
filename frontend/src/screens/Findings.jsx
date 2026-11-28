import { Fragment, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getFindings, lastScan } from "../api/client";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

export default function Findings() {
  const params = useParams();
  const id = params.id || lastScan();
  const [findings, setFindings] = useState([]);
  const [severity, setSeverity] = useState("All");
  const [category, setCategory] = useState("All");
  const [open, setOpen] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    getFindings(id)
      .then((d) => setFindings(d.findings || []))
      .catch((e) => setError(e.message));
  }, [id]);

  if (!id) {
    return (
      <div>
        <h2>Findings</h2>
        <p>No scan yet. Start one on the <Link to="/">Target Setup</Link> screen.</p>
      </div>
    );
  }

  const categories = [...new Set(findings.map((f) => f.category))];
  const shown = findings
    .filter((f) => severity === "All" || f.severity === severity)
    .filter((f) => category === "All" || f.category === category)
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));

  return (
    <div>
      <h2>Findings</h2>
      <p>Scan {id} | <Link to={"/report/" + id}>Make report</Link></p>
      {error && <p style={{ color: "red" }}>{error}</p>}

      <p>
        Severity:{" "}
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option>All</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>{" "}
        Category:{" "}
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option>All</option>
          {categories.map((c) => <option key={c}>{c}</option>)}
        </select>{" "}
        Showing {shown.length} of {findings.length}
      </p>

      <table border="1" cellPadding="4" style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr><th>ID</th><th>Severity</th><th>Category</th><th>Title</th><th>Endpoint</th></tr>
        </thead>
        <tbody>
          {shown.map((f) => (
            <Fragment key={f.id}>
              <tr
                key={f.id}
                onClick={() => setOpen(open === f.id ? null : f.id)}
                style={{ cursor: "pointer" }}
              >
                <td>{f.id}</td>
                <td><span className={"sev sev-" + String(f.severity || "").toLowerCase()}>{f.severity}</span></td>
                <td>{f.category}</td>
                <td>{f.title}</td>
                <td>{f.endpoint}</td>
              </tr>
              {open === f.id && (
                <tr key={f.id + "-detail"}>
                  <td colSpan="5" style={{ textAlign: "left" }}>
                    <p><b>Confidence:</b> {f.confidence} | <b>Status:</b> {f.status}</p>
                    <p><b>Impact:</b> {f.impact}</p>
                    <p><b>Fix:</b> {f.fix}</p>
                    {f.evidence && (
                      <pre style={{ whiteSpace: "pre-wrap" }}>
                        {JSON.stringify(f.evidence, null, 2)}
                      </pre>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
      <p><small>Click a row to see impact, fix and masked evidence.</small></p>
    </div>
  );
}