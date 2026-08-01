import { useState } from "react";
import "./App.css";
import type { AnalysisResult } from "./types";
import UploadBox from "./components/UploadBox";
import StatsBar from "./components/StatsBar";
import Timeline from "./components/Timeline";
import FindingsTable from "./components/FindingsTable";

function App() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="app">
      <h1>ProxyLogAnalyzer</h1>
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
      />

      {loading && <div className="status loading">Analyzing&hellip;</div>}
      {error && <div className="status error">Error: {error}</div>}

      {result && (
        <>
          <StatsBar stats={result.stats} />
          <Timeline events={result.timeline} />
          <FindingsTable findings={result.findings} />
        </>
      )}
    </div>
  );
}

export default App;
