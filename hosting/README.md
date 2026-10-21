# One address for Windows and WSL tools

This setup deliberately uses independent Streamlit servers rather than a single
Python process: PCAP decoding requires Linux, Python 3.10, a native `.so` engine,
and pinned protobuf dependencies. The shared wrapper adds a same-tab navigation
menu without modifying the standalone tools.

| Public path | Backend (loopback only) | Environment |
| --- | --- | --- |
| `/` | 8510 | Root Windows `.venv` |
| `/readout/` | 8511 | Root Windows `.venv` |
| `/pcap/` | 8512 | WSL `pcap_decoder/.venv` |
| `/someip/` | 8513 | Root Windows `.venv` (workspace dependencies) |
| `/can/` | 8514 | Windows `can_decoder/.venv` |

Caddy preserves each prefix, including Streamlit's WebSocket, upload, and static
asset routes. The menu uses same-origin links; users never need backend addresses
or an iframe. Switching tools opens a separate app session, not a shared
`st.session_state`. Returning to a tool can reset its session/widgets; download
results before leaving and cancel active jobs before stopping the stack.

## Prerequisites

From the repository root in Windows PowerShell:

```powershell
.\setup_uv.ps1
uv sync --all-packages
```

The second command includes the SOME/IP workspace dependencies in the root
environment. The CAN viewer retains its separate environment.

Install [Caddy](https://caddyserver.com/docs/install) and put `caddy.exe` on PATH,
or pass its executable path to `-CaddyPath`. For example, with Windows Package
Manager:

```powershell
winget install --id CaddyServer.Caddy --exact
```

Prepare the PCAP decoder inside the desired WSL distribution using
[its setup instructions](../pcap_decoder/README.md#streamlit-ui-wsl). Keep its
Linux Python 3.10 environment separate from the root Windows environment.
Install its native runtime prerequisites (`libpcap`, `zstd`) as documented there.
No separate PCAP server needs to be started manually.

WSL's Windows-to-Linux localhost forwarding must be enabled (the WSL default).
Verify the distribution name with `wsl --list --quiet`; this launcher's default is
`Ubuntu22`. Windows drive paths are translated with `wslpath`, including paths
containing spaces.

## Start

```powershell
.\hosting\start.ps1 -Distro Ubuntu22
```

Open **http://localhost:8080**. Keep the launching terminal open.
The launcher checks dependencies and free backend ports, validates Caddy,
waits for each server's health endpoint, and stops the stack if a child exits.
Ctrl+C stops the servers it started, including the supervised WSL server,
without terminating the WSL distribution or unrelated processes.
Per-process stdout/stderr logs remain in the temporary directory printed by
the launcher for troubleshooting.
For automation, pass `-StopFile C:\path\to\stop-file` and create that file to
request the same graceful shutdown. The file must not already exist at startup.

Optional executable and CAN source:

```powershell
.\hosting\start.ps1 -Distro Ubuntu22 -CaddyPath C:\tools\caddy.exe `
    -CanParquet C:\logs\decoded.parquet
```

The CAN viewer uses that server-side Parquet file for all users. Without it,
the existing viewer selects the first Parquet file in `can_decoder`, or shows
its existing "No .parquet file found" message. Decode a CAN capture first.
This setup does not add browser-based CAN conversion/upload.

## Share with colleagues

For a **trusted-network test only**:

```powershell
.\hosting\start.ps1 -Address http://YOUR-WINDOWS-HOST:8080
```

Allow only the front-door port through Windows Firewall for the intended
network. Do not expose backend ports 8510-8514. Caddy automatically proxies
WebSockets; do not strip `/pcap`, `/readout`, `/someip`, or `/can`.

**This launcher does not add authentication.** The tools can access server
files, network shares and credentials, and invoke analysis jobs. Before using a
shared or internet-reachable deployment, put the *entire site*, including health,
WebSocket and upload endpoints, behind your organization's authenticated VPN or
SSO gateway. Do not expose these tools to untrusted users. OS keychain credentials
belong to the server account, not to each browser user.

For HTTPS, pass an address such as `https://fault-tools.example.com`.
Caddy requests certificates automatically if DNS and ACME connectivity permit;
the launcher does not create DNS records, certificates, firewall rules or SSO.
For an internal hostname, configure the organization's certificate/key in
`Caddyfile` (or terminate TLS at the authenticated gateway). The launcher must
be able to reach and trust the supplied address for its readiness check.
For unattended production hosting, supervise the launcher using your
organization's Windows service tooling under a dedicated service account
with the required WSL distribution and network permissions.

## Files, credentials and persistence

- Readout/CAN/SOME-IP server paths refer to **Windows** on the hosting computer.
- PCAP server paths refer to **WSL**; Windows drive paths are translated by the
  existing PCAP UI to `/mnt/...`. Browser uploads go to WSL as before.
- PCAP SDB caches, Artifactory credentials and TokenUpdater remain in the WSL
  account. Windows environment variables are not automatically copied to WSL;
  configure credentials there or use the PCAP UI.
- PCAP Streamlit secrets/config are read from its working directory,
  `pcap_decoder`, as for the standalone WSL launch. Windows hosted apps run from
  the repository root; configure shared Windows secrets there. Per-tool themes
  in subdirectories are not automatically applied to the shared deployment.
- Windows must still have the required SMB/VPN/ConfigHub access; WSL needs its
  own Artifactory/network access.
- Switching apps performs a normal same-tab navigation. An active PCAP decoding
  subprocess may outlive its browser session; cancel it before leaving if needed.
  This is not a cross-session job manager.

## Validation

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s hosting -p test_hosting.py -v
caddy validate --config hosting\Caddyfile --adapter caddyfile
```
