// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, compile, or install dependencies.
// Type annotations and imports exercise parsing, not a deployed service.
import { exec, execFile } from "node:child_process";
import { Agent } from "node:https";
import type { Express, Request, Response } from "express";

function vulnerableRoutes(app: Express): void {
  app.post("/fixture", (request: Request, response: Response) => {
    const supplied = request.body.command;
    const forwarded = supplied;
    // ruleid: localguard.security.node-request-shell
    exec(forwarded);
  });
}

function cleanRoutes(app: Express): void {
  app.post("/fixture", (request: Request, response: Response) => {
    const supplied = request.body.argument;
    // ok: localguard.security.node-request-shell
    execFile("fixture-tool", [supplied]);
    // ok: localguard.security.node-request-shell
    exec("fixture-tool --version");
  });
}

function vulnerableTls(): Agent {
  // ruleid: localguard.security.node-tls-no-cert-validation
  return new Agent({ rejectUnauthorized: false });
}

function cleanTls(): Agent {
  // ok: localguard.security.node-tls-no-cert-validation
  return new Agent({ rejectUnauthorized: true });
}
