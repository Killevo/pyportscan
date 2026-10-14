# pyportscan

A simple, fast, dependency-free **multithreaded TCP port scanner** written in Python.

> ⚠️ **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. The author is not responsible for misuse.

## Features

- Pure Python 3.9+ standard library, no installation of packages needed
- Multithreaded scanning with configurable thread count and timeout
- Flexible port syntax: single, list, range, or a mix
- Service name detection (via the system services database)
- Optional banner grabbing
- JSON report export
- Clean CLI with `--help`

## Requirements

- Python 3.9 or newer

## Installation

```bash
git clone https://github.com/Killevo/pyportscan.git
cd pyportscan
```

## Usage

```bash
python3 pyportscan.py <target> [options]
```

| Option | Description | Default |
|---|---|---|
| `-p`, `--ports` | Ports to scan (`80`, `22,80,443`, `1-1024`, `22,8000-8100`) | `1-1024` |
| `-t`, `--threads` | Number of worker threads | `100` |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `-b`, `--banner` | Try to grab service banners | off |
| `-o`, `--output` | Save results to a JSON file | none |
| `-v`, `--version` | Show version | |

### Examples

```bash
# Scan the default range (1-1024)
python3 pyportscan.py scanme.nmap.org

# Scan specific ports with banner grabbing
python3 pyportscan.py 192.168.1.10 -p 22,80,443,8080 -b

# Scan all ports, 300 threads, save JSON report
python3 pyportscan.py 192.168.1.10 -p 1-65535 -t 300 --timeout 0.5 -o report.json
```

### Sample output

```
[*] Target : 192.168.1.10 (192.168.1.10)
[*] Ports  : 1024 | Threads: 100 | Timeout: 1.0s

[+]    22/tcp  open  ssh  | SSH-2.0-OpenSSH_9.6
[+]    80/tcp  open  http | HTTP/1.0 200 OK

[*] Done. 2 open port(s) found.
```

## How it works

For each port, the scanner performs a full TCP connect (`connect_ex`). If the connection succeeds, the port is reported as open. This is a *TCP connect scan*, so it needs no special privileges but is more visible in logs than stealth scans.

## Limitations

- IPv4 only
- TCP only (no UDP)
- Very high thread counts may cause false negatives on slow or rate-limited networks

## Contributing

Pull requests are welcome. Please open an issue first to discuss larger changes.

## License

Released under the [MIT License](LICENSE).
