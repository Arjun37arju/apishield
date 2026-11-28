import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";

import TargetSetup from "./screens/TargetSetup";
import AuthSettings from "./screens/AuthSettings";
import ScanProfile from "./screens/ScanProfile";
import ScanProgress from "./screens/ScanProgress";
import Findings from "./screens/Findings";
import ReportView from "./screens/ReportView";
import ScanHistory from "./screens/ScanHistory";

const TABS = [
  ["/", "Target Setup"],
  ["/auth", "Auth"],
  ["/profile", "Profile"],
  ["/progress", "Progress"],
  ["/findings", "Findings"],
  ["/report", "Report"],
  ["/history", "History"],
];

export default function App() {
  return (
    <BrowserRouter>
      <header className="app-header">
        <div className="brand">
          <svg className="brand-logo" viewBox="0 0 32 32" aria-hidden="true">
            <defs>
              <linearGradient id="shield" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stopColor="#60a5fa" />
                <stop offset="1" stopColor="#22d3ee" />
              </linearGradient>
            </defs>
            <path
              d="M16 2 4 6.5v8.2c0 7.2 4.9 12.7 12 15.3 7.1-2.6 12-8.1 12-15.3V6.5L16 2z"
              fill="none"
              stroke="url(#shield)"
              strokeWidth="2.2"
              strokeLinejoin="round"
            />
            <path
              d="m10.5 16.2 4 4 7-8"
              fill="none"
              stroke="url(#shield)"
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <div className="brand-text">
            <span className="brand-name">API-Gapwolf</span>
            <span className="brand-tag">Local-first API security testing</span>
          </div>
        </div>

        <nav className="tabs">
          {TABS.map(([to, label]) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) => (isActive ? "tab active" : "tab")}
            >
              {label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="page">
        <Routes>
          <Route path="/" element={<TargetSetup />} />
          <Route path="/auth" element={<AuthSettings />} />
          <Route path="/profile" element={<ScanProfile />} />
          <Route path="/progress" element={<ScanProgress />} />
          <Route path="/progress/:id" element={<ScanProgress />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:id" element={<Findings />} />
          <Route path="/report" element={<ReportView />} />
          <Route path="/report/:id" element={<ReportView />} />
          <Route path="/history" element={<ScanHistory />} />
        </Routes>
      </main>
    </BrowserRouter>
  );
}