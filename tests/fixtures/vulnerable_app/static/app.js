// Deliberately vulnerable client-side JS — static-analysis test fixture only.
// See app.py for the marker-comment convention (# VULN / # SAFE / # MISSED).

const API_KEY = "REDACTED_FAKE_SECRET_NOT_A_REAL_KEY_11111";  // VULN: hardcoded_secret

function showMessage(userInput) {
  const box = document.getElementById("message-box");
  box.innerHTML = userInput;  // VULN: xss
}

function showMessageSafe(userInput) {
  const box = document.getElementById("message-box");
  box.textContent = userInput;  // SAFE: textContent does not parse HTML
}

function legacyWrite(param) {
  document.write(param);  // VULN: xss
}

function runUserExpression(userCode) {
  return eval(userCode);  // VULN: insecure_deserialization
}

function loadRemoteData(userUrl) {
  return fetch(userUrl).then((r) => r.json());  // VULN: ssrf
}

function loadRemoteDataSafe(userUrl) {
  const allowed = new Set(["https://api.example.com/data"]);
  if (!allowed.has(userUrl)) {
    throw new Error("URL not allowlisted");
  }
  return fetch(userUrl).then((r) => r.json());  // FALSE_POSITIVE_EXPECTED: ssrf (allowlisted above, but the line-based scanner can't see that check)
}
