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
   problem is solved (401 just means no API key was sent). **If Node still
   fails, the script repairs itself**: it widens the bundle to every root
   Windows trusts, rewrites it and tests again, before asking you to do
   anything by hand.
5. Prints `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` and the WinINET proxy settings.

It ends with a pass/fail summary:

```
   [ OK ]  PEM file written              C:\Users\you\proxy-ca.pem
   [ OK ]  CA certificate(s) in bundle   2 found
   [ OK ]  NODE_EXTRA_CA_CERTS persisted
   [ OK ]  Node.js TLS test
```

The Node.js line is the authoritative one — it exercises exactly what Claude
Code does. The others only explain a failure when it does not pass.

### Safety

It creates the `.pem` file and sets one user environment variable. Nothing else
is deleted or modified:

- An existing `proxy-ca.pem` is copied to `proxy-ca.pem.bak-<timestamp>` before
  being rewritten, and its certificates are carried into the new bundle.
- If `NODE_EXTRA_CA_CERTS` already pointed at a different bundle, those
  certificates are carried over too, so another tool's setup is not broken.
- A re-run that would change nothing leaves the file untouched, so repeated
  runs do not pile up backups.
- `setx` is verified by reading the value back, and falls back to the .NET API
  if it did not stick.

### When the first attempt is not enough

The targeted chain — the leaf, the intermediates sent during the handshake, and
the issuers walked up through the Windows trust stores — is tried first. If Node
still rejects it, the script adds every root Windows trusts, rewrites the bundle
and retests, so Node ends up trusting exactly what Windows trusts. Only if that
also fails does it stop and print manual `certmgr.msc` export steps, rather than
leaving behind a PEM that looks right but does not work. Save the exported CA
over `proxy-ca.pem` and re-run — the script keeps what you exported and merges
it.

Note that the CA named in the `ISSUER` line does not itself have to be in the
bundle. It is often an intermediate sent during the handshake, anchored by a
root that is in the bundle; the Node.js test is what settles it.

**After it finishes, close VS Code completely and reopen it.** "Reload Window"
is not enough — `setx` only reaches newly started processes.
