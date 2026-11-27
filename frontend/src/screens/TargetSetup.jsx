import { useState } from "react";
import { validateTarget } from "../api/client";

export default function TargetSetup() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function handleValidate(e) {
    e.preventDefault();

    setError("");
    setResult(null);

    try {
      const data = await validateTarget(url);
      setResult(data);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <h2>Target Setup</h2>

      <form onSubmit={handleValidate}>
        <input
          type="text"
          placeholder="http://127.0.0.1:5000"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ width: "400px", marginRight: "10px" }}
        />

        <button type="submit">
          Validate Target
        </button>
      </form>

      {error && (
        <p style={{ color: "red" }}>
          {error}
        </p>
      )}

      {result && (
        <pre>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}