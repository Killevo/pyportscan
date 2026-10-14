#!/usr/bin/env python3
"""pyportscan - a simple multithreaded TCP port scanner.

Only scan systems you own or have explicit permission to test.
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

__version__ = "1.0.0"

HTTP_PORTS = {80, 8000, 8080, 8888}


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or a mix like '22,80,8000-8100'."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"Port out of range (1-65535): {p}")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float, grab_banner: bool):
    """Return a result dict if the port is open, otherwise None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = ""
            if grab_banner:
                try:
                    if port in HTTP_PORTS:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(1024).decode(errors="ignore").strip()
                    banner = data.splitlines()[0][:100] if data else ""
                except OSError:
                    pass
            return {"port": port, "service": service_name(port), "banner": banner}
    except OSError:
        return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyportscan",
        description="Simple multithreaded TCP port scanner.",
        epilog="Use only on systems you own or are authorized to test.",
    )
    p.add_argument("target", help="Hostname or IPv4 address")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="Ports: '80', '22,80,443', '1-1024' (default: 1-1024)")
    p.add_argument("-t", "--threads", type=int, default=100,
                   help="Number of worker threads (default: 100)")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Connection timeout in seconds (default: 1.0)")
    p.add_argument("-b", "--banner", action="store_true",
                   help="Try to grab service banners")
    p.add_argument("-o", "--output", help="Save results to a JSON file")
    p.add_argument("-v", "--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p


def main() -> int:
    args = build_parser().parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid port specification: {e}", file=sys.stderr)
        return 2

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {args.target}", file=sys.stderr)
        return 2

    print(f"[*] Target : {args.target} ({ip})")
    print(f"[*] Ports  : {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s")
    print(f"[*] Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    results = []
    executor = ThreadPoolExecutor(max_workers=max(1, args.threads))
    try:
        futures = [executor.submit(scan_port, ip, p, args.timeout, args.banner)
                   for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
                line = f"[+] {res['port']:>5}/tcp  open  {res['service']}"
                if res["banner"]:
                    line += f"  | {res['banner']}"
                print(line)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        executor.shutdown(wait=False, cancel_futures=True)
        return 130
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    results.sort(key=lambda r: r["port"])
    print(f"\n[*] Done. {len(results)} open port(s) found.")

    if args.output:
        report = {
            "target": args.target,
            "ip": ip,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "ports_scanned": len(ports),
            "open_ports": results,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
