import type { AnalysisResult } from "../types";

interface Props {
  onStart: () => void;
  onSuccess: (result: AnalysisResult) => void;
  onError: (message: string) => void;
}

export default function UploadBox({ onStart, onSuccess, onError }: Props) {
  const handleFile = (file: File) => {
    onStart();
    const form = new FormData();
    form.append("file", file);
    fetch("http://localhost:5000/api/upload", { method: "POST", body: form })
      .then(async response => {
        if (!response.ok) {
          let message = response.statusText;
          try {
            const body = await response.json();
            message = body.error;
          } catch {
          }
          onError(message);
        } else {
          const data = await response.json();
          onSuccess(data);
        }
      })
      .catch(error => onError(String(error)));
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
    </div>
  );
}
