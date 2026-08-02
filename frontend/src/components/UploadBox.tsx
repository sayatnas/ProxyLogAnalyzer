import type { AnalysisResult } from "../types";
import { authedFetch, AuthError } from "../api";


interface Props {
  onStart: () => void;
  onSuccess: (result: AnalysisResult) => void;
  onError: (message: string) => void;
  onSessionExpired: () => void;
}

export default function UploadBox({ onStart, onSuccess, onError, onSessionExpired }: Props) {
  const handleFile = (file: File) => {
    onStart();
    const form = new FormData();
    form.append("file", file);
    authedFetch("/api/upload", { method: "POST", body: form })
      .then(async response => {
        if (!response.ok) {
          let message = response.statusText;
          try {
            const body = await response.json();
            if (body.error) message = body.error;
          } catch {
          }
          onError(message);
        } else {
          const data = await response.json();
          onSuccess(data);
        }
      })
      .catch(error => {
        if (error instanceof AuthError) {
          onSessionExpired();
        } else {
          onError(String(error));
        }
      });
  };
  // The example log ships with the site (frontend/public), so the reviewer
  // can try the app without hunting for a file.
  const handleSample = async () => {
    try {
      const response = await fetch("/sample_day.log");
      if (!response.ok) throw new Error(`sample fetch failed (${response.status})`);
      const blob = await response.blob();
      handleFile(new File([blob], "sample_day.log"));
    } catch (error) {
      onError(String(error));
    }
  };

  return (
    <div className="upload">
      <label className="upload-label">
        Upload a proxy log (.log / .csv)
        <input
          type="file"
          accept=".log,.txt,.csv"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) {
              handleFile(f);
            }
          }}
        />
      </label>
      <button className="link sample-link" onClick={handleSample}>
        or analyze the included example log (one day, planted anomalies)
      </button>
    </div>
  );
}
