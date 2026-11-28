import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getScan, cancelScan, lastScan } from "../api/client";

const DONE = ["Completed", "Cancelled", "Failed"];

export default function ScanProgress() {
  const params = useParams();
  const id = params.id || lastScan();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return undefined;
    let stop = false;
    let timer = null;
    async function poll() {
      try {
        const data = await getScan(id);
        if (stop) return;
        setScan(data);
        setError("");
        if (!DONE.includes(data.state)) timer = setTimeout(poll, 1000);
      } catch (err) {
        if (!stop) setError(err.message);
      }
    }
    poll();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [id]);

  async function handleCancel() {
    try {
      setScan(await cancelScan(id));
    } catch (err) {
      setError(err.message);
    }
  }

  if (!id) {
    return (
      <div>
        <h2>Scan Progress</h2>
        <p>No scan yet. Start one on the <Link to="/">Target Setup</Link> screen.</p>
      </div>
    );
  }

  const running = scan && !DONE.includes(scan.state);

  return (
    <div>
      <h2>Scan Progress</h2>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {scan && (
        <>
          <p>
            <b>Scan</b> {scan.id} | <b>Target</b> {scan.scope} | <b>State</b> {scan.state}
            {" | "}<b>Requests</b> {scan.requests_made} | <b>Findings</b>{" "}
            {(scan.findings || []).length}
          </p>
          {scan.error && <p style={{ color: "red" }}>{scan.error}</p>}
          {!running && (() => {
            const results = scan.results || [];
            const errors = results.filter((r) => r.outcome === "Error").length;
            if (scan.requests_made === 0 || (results.length && errors * 2 >= results.length)) {
              return (
                <p style={{ color: "orange" }}>
                  Warning: {scan.requests_made === 0 ? "no requests were sent" : "most checks ended in Error"}.
                  "Completed" does not mean the API was tested. Check the Details column below.
                </p>
              );
            }
            return null;
          })()}
          {running && <button onClick={handleCancel}>Cancel scan</button>}
          {!running && (
            <p>
              <Link to={"/findings/" + scan.id}>View findings</Link>
              {" | "}
              <Link to={"/report/" + scan.id}>Make report</Link>
            </p>
          )}
          <table border="1" cellPadding="4" style={{ borderCollapse: "collapse", marginTop: 12 }}>
            <thead>
              <tr><th>Check</th><th>Result</th><th>Details</th></tr>
            </thead>
            <tbody>
              {(scan.results || []).map((r, i) => (
                <tr key={i}>
                  <td>{r.name || r.check_id}</td>
                  <td><span className={"out out-" + String(r.outcome || "").toLowerCase().replace(/[^a-z]+/g, "-")}>{r.outcome}</span></td>
                  <td>{r.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}