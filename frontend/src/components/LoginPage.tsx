import { useState } from "react";
import { login, setToken } from "../api";

interface Props {
  onLoggedIn: () => void;
}

export default function LoginPage({ onLoggedIn }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // preventDefault stops the browser's own form submission, which would reload
  // the page and wipe React's state.
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const token = await login(username, password);
      setToken(token);
      onLoggedIn();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app">
      <h1>ProxyLogAnalyzer</h1>
      <form className="login" onSubmit={handleSubmit}>
        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>

        <button type="submit" disabled={busy}>Log in</button>

        {error && <p className="status error">{error}</p>}
      </form>
    </div>
  );
}
