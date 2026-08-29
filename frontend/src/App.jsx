import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleCheck = async () => {
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:8000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error("Server error — please try again.");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: "600px", margin: "60px auto", fontFamily: "sans-serif" }}>
      <h1>Phishing URL Checker</h1>
      <p>Enter a URL to check if it looks legitimate or suspicious.</p>

      <div style={{ display: "flex", gap: "8px", marginTop: "20px" }}>
        <input
          type="text"
          id="url-input"
          name="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          style={{ flex: 1, padding: "10px", fontSize: "16px" }}
        />
        <button onClick={handleCheck} disabled={loading} style={{ padding: "10px 20px" }}>
          {loading ? "Checking..." : "Check"}
        </button>
      </div>

      {error && <p style={{ color: "red", marginTop: "20px" }}>{error}</p>}

      {result && (
        <div
          style={{
            marginTop: "30px",
            padding: "20px",
            borderRadius: "8px",
            backgroundColor: result.prediction === "Phishing" ? "#eb0d0d" : "#13e833",
          }}
        >
          <h2>
            {result.prediction === "Phishing" ? "⚠️ Potential Phishing" : "✅ Legitimate"}
          </h2>
          <p><strong>Confidence:</strong> {result.confidence}%</p>
          <p><strong>Why?</strong></p>
          <ul>
            {result.reasons.map((reason, i) => (
              <li key={i}>{reason}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;