import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { createReport, reportUrl, lastScan } from "../api/client";

export default function ReportView() {
  const params = useParams();
  const id = params.id || lastScan();
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleMake() {
    setError("");
    setBusy(true);
    try {
      setReport(await createReport(id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (!id) {
    return (
      <div>
        <h2>Report</h2>
        <p>No scan yet. Start one on the <Link to="/">Target Setup</Link> screen.</p>
      </div>
    );
  }

  return (
    <div>
      <h2>Report</h2>
      <p>Scan {id} | <Link to={"/findings/" + id}>View findings</Link></p>
      <p style={{ color: "orange" }}>
        Warning: the report lists real weaknesses. Share it carefully.
      </p>
      <button onClick={handleMake} disabled={busy}>
        {busy ? "Making PDF..." : "Make PDF report"}
      </button>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {report && (
        <p>
          Report ready: <b>{report.file_name}</b>
          <br />
          <a href={reportUrl(report.file_name) + "?download=1"} rel="noreferrer">Download PDF</a>{" | "}<a href={reportUrl(report.file_name)} target="_blank" rel="noreferrer">
            Open PDF
          </a>
        </p>
      )}
    </div>
  );
}