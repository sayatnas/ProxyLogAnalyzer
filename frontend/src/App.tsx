import { useState } from "react";
import "./App.css";
import type { AnalysisResult } from "./types";
import { clearToken, getToken } from "./api";
import LoginPage from "./components/LoginPage";
import UploadBox from "./components/UploadBox";
import StatsBar from "./components/StatsBar";
import SummaryPanel from "./components/SummaryPanel";
import Timeline from "./components/Timeline";
import FindingsTable from "./components/FindingsTable";

function App() {
  // Initialising from localStorage means a page refresh keeps you logged in:
  // the token outlives React's state.
  const [loggedIn, setLoggedIn] = useState(() => getToken() !== null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!loggedIn) {
    return <LoginPage onLoggedIn={() => setLoggedIn(true)} />;
  }

  return (
    <div className="app">
      <header className="topbar">
        <h1>ProxyLogAnalyzer</h1>
        <button
          className="link"
          onClick={() => {
            clearToken();
            setLoggedIn(false);
            setResult(null);
          }}
        >
          Log out
        </button>
      </header>
      <p className="muted">Upload a proxy log to analyze it for anomalies.</p>

      <UploadBox
        onStart={() => {
          setLoading(true);
          setError(null);
          setResult(null);
        }}
        onSuccess={(data) => {
          setResult(data);
          setLoading(false);
        }}
        onError={(msg) => {
          setError(msg);
          setLoading(false);
        }}
        onSessionExpired={() => {
          setLoggedIn(false);
          setLoading(false);
        }}
      />

      {loading && <div className="status loading">Analyzing&hellip;</div>}
      {error && <div className="status error">Error: {error}</div>}

      {result && (
        <>
          <StatsBar stats={result.stats} />
          <SummaryPanel key={result.upload_id} uploadId={result.upload_id} />
          <Timeline events={result.timeline} />
          <FindingsTable
            findings={result.findings}
            uploadId={result.upload_id}
            detectors={result.detectors}
          />
        </>
      )}
    </div>
  );
}

export default App;
