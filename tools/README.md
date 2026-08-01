# tools

Helper scripts that are not part of the DeepPTMPred model code.

## `fix-claude-code-cert-windows.ps1`

Diagnoses and fixes this Claude Code error on Windows:

```
API Error: Unable to connect to API: Self-signed certificate detected.
Check your proxy or corporate SSL certificates
```

A campus firewall, VPN or antivirus is terminating TLS to `api.anthropic.com`
and re-signing it with its own CA. Windows and your browser trust that CA,
but Node.js ships its own CA bundle and does not — so Claude Code fails while
everything else keeps working.

Run in a normal (non-admin) PowerShell window:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fix-claude-code-cert-windows.ps1
```

What it does:

1. Performs a TLS handshake and prints the certificate **issuer**, which names
   the product doing the interception.
2. Writes the certificate chain to `%USERPROFILE%\proxy-ca.pem`.
3. Sets `NODE_EXTRA_CA_CERTS` via `setx` (permanent) and `$env:` (current session).
4. Verifies the variable and runs both a PowerShell and a Node.js HTTPS request.
   The Node test is the one that matters — `HTTP 401` means the certificate
   problem is solved (401 just means no API key was sent).
5. Prints `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` and the WinINET proxy settings.

It only creates the `.pem` file and sets one user environment variable. Nothing
is deleted or modified.

If the intercepting CA cannot be found on the wire or in the Windows trust
stores, the script says so and prints manual `certmgr.msc` export steps rather
than leaving behind a PEM that looks right but does not work.

**After it finishes, close VS Code completely and reopen it.** "Reload Window"
is not enough — `setx` only reaches newly started processes.
