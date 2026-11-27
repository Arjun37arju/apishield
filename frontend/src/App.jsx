import { BrowserRouter, Routes, Route, Link } from "react-router-dom";

import TargetSetup from "./screens/TargetSetup";
import AuthSettings from "./screens/AuthSettings";
import ScanProfile from "./screens/ScanProfile";
import ScanProgress from "./screens/ScanProgress";
import Findings from "./screens/Findings";
import ReportView from "./screens/ReportView";
import ScanHistory from "./screens/ScanHistory";

export default function App() {
  return (
    <BrowserRouter>
      <div style={{ padding: 20 }}>
        <h1>APIShield</h1>

        <nav style={{ display: "flex", gap: "12px", marginBottom: "20px" }}>
          <Link to="/">Target Setup</Link>
          <Link to="/auth">Auth</Link>
          <Link to="/profile">Profile</Link>
          <Link to="/progress">Progress</Link>
          <Link to="/findings">Findings</Link>
          <Link to="/report">Report</Link>
          <Link to="/history">History</Link>
        </nav>

        <Routes>
          <Route path="/" element={<TargetSetup />} />
          <Route path="/auth" element={<AuthSettings />} />
          <Route path="/profile" element={<ScanProfile />} />
          <Route path="/progress" element={<ScanProgress />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/report" element={<ReportView />} />
          <Route path="/history" element={<ScanHistory />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}