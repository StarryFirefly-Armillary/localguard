// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, compile, or fetch modules.
// Commands are never started; this is only scanner input.
package securityfixtures

import (
    "crypto/tls"
    "net/http"
    "os/exec"
)

func vulnerableCommand(request *http.Request) {
    supplied := request.FormValue("fixture_command")
    command := "fixture-tool " + supplied
    // ruleid: localguard.security.go-request-shell
    _ = exec.Command("sh", "-c", command)
}

func cleanCommand(request *http.Request) {
    supplied := request.URL.Query().Get("fixture_argument")
    // ok: localguard.security.go-request-shell
    _ = exec.Command("fixture-tool", supplied)
    // ok: localguard.security.go-request-shell
    _ = exec.Command("sh", "-c", "fixture-tool --version")
}

func vulnerableTLS() {
    // ruleid: localguard.security.go-tls-no-cert-validation
    _ = &tls.Config{InsecureSkipVerify: true}
}

func cleanTLS() {
    // ok: localguard.security.go-tls-no-cert-validation
    _ = &tls.Config{InsecureSkipVerify: false}
}
