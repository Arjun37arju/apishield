import { useEffect, useState } from "react";
import { getHealth } from "./api/client";

export default function App() {
  const [status, setStatus] = useState("checking...");

  useEffect(() => {
    getHealth()
      .then((d) => setStatus(d.status === "ok" ? "backend OK" : "backend problem"))
      .catch(() => setStatus("backend not reachable"));
  }, []);

  return (
    <div style={{ padding: 24 }}>
      <h1>APIShield</h1>
      <p>{status}</p>
    </div>
  );
}
