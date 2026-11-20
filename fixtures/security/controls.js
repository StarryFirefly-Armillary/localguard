// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE or install dependencies.
// No application is started; functions are only parsed by the scanner.
const child = require("child_process");
const https = require("https");

function vulnerableRoutes(app) {
  app.get("/fixture", (req, res) => {
    const supplied = req.query.command;
    const command = "fixture-tool " + supplied;
    // ruleid: localguard.security.node-request-shell
    child.exec(command);
  });
}

function cleanRoutes(app) {
  app.get("/fixture", (req, res) => {
    const supplied = req.query.argument;
    // ok: localguard.security.node-request-shell
    child.execFile("fixture-tool", [supplied]);
    // ok: localguard.security.node-request-shell
    child.exec("fixture-tool --version");
  });
}

function vulnerableTls(endpoint) {
  // ruleid: localguard.security.node-tls-no-cert-validation
  return https.request(endpoint, { rejectUnauthorized: false });
}

function cleanTls(endpoint) {
  // ok: localguard.security.node-tls-no-cert-validation
  return https.request(endpoint, { rejectUnauthorized: true });
}

function cleanUnrelatedOption() {
  // ok: localguard.security.node-tls-no-cert-validation
  const displayOnly = { rejectUnauthorized: false };
  // ok: localguard.security.node-request-shell
  const description = "child.exec(req.query.command)";
  return { displayOnly, description };
}
