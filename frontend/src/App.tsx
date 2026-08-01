// App root component.

import { useState } from "react";

function App() {
  const [message, setMessage] = useState<string>("(nothing fetched yet)");

  const fetchHello = async () => {
    const response = await fetch("http://localhost:5000/api/hello");
    const data = await response.json();
    setMessage(`${data.message} at ${data.time}`);
  };

  return (
    <main style={{ fontFamily: "sans-serif", padding: "2rem" }}>
      <h1>Spike: browser → Flask → browser</h1>

      {/* TODO(you): add onClick={fetchHello} to this button */}
      <button onClick={() => fetchHello()}>Call the kitchen</button>

      <p>Server says: {message}</p>
    </main>
  );
}

export default App;
