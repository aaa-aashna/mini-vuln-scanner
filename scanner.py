import argparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class Finding:
    target: str
    port: int
    protocol: str
    service: str
    version: str
    cve: str
    severity: str
    description: str


def load_vuln_db(path: str = "vuln_db.json") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[!] Vulnerability database not found: {path}")
        return {}
    except json.JSONDecodeError:
        print(f"[!] Invalid vulnerability database: {path}")
        return {}


def parse_ports(port_spec: str) -> list[int]:
    ports = set()

    for part in port_spec.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            start, end = part.split("-", 1)

            start = int(start)
            end = int(end)

            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range")

            ports.update(range(start, end + 1))

        else:
            port = int(part)

            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")

            ports.add(port)

    if not ports:
        raise ValueError("No valid ports specified")

    return sorted(ports)


def identify_service(port: int) -> str:
    services = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        8080: "http",
    }

    return services.get(port, "unknown")


def scan_port(target: str, port: int, timeout: float = 0.5) -> Optional[dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result != 0:
            return None

        service = identify_service(port)
        banner = ""

        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except (socket.timeout, ConnectionResetError, OSError):
            pass

        return {
            "port": port,
            "protocol": "tcp",
            "service": service,
            "banner": banner,
        }

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

    finally:
        sock.close()


def match_vulnerabilities(
    target: str,
    port_info: dict,
    vuln_db: dict,
) -> list[Finding]:

    findings = []

    service = port_info["service"]
    banner = port_info["banner"]

    if service not in vuln_db or not banner:
        return findings

    service_db = vuln_db[service]

    for version, vulnerability in service_db.items():

        if version.lower() not in banner.lower():
            continue

        if isinstance(vulnerability, dict):
            cve = vulnerability.get("cve", "UNKNOWN")
            severity = vulnerability.get("severity", "UNKNOWN")
            description = vulnerability.get("description", "")
        else:
            # Backward compatibility with the original database format.
            description = vulnerability

            if " - " in vulnerability:
                description, cve = vulnerability.rsplit(" - ", 1)
            else:
                cve = "UNKNOWN"

            severity = "UNKNOWN"

        findings.append(
            Finding(
                target=target,
                port=port_info["port"],
                protocol=port_info["protocol"],
                service=service,
                version=version,
                cve=cve,
                severity=severity,
                description=description,
            )
        )

    return findings


def print_scan_results(
    target: str,
    open_ports: list[dict],
    findings: list[Finding],
    ports_scanned: int,
) -> None:

    print("\n" + "=" * 48)
    print("           MINI VULNERABILITY SCANNER")
    print("=" * 48)

    print(f"\nTarget: {target}")
    print(f"Ports scanned: {ports_scanned}")

    print("\nOPEN PORTS")
    print("-" * 48)

    if not open_ports:
        print("No open ports found.")
    else:
        for port_info in sorted(open_ports, key=lambda x: x["port"]):
            banner = port_info["banner"] or "No banner"
            print(
                f"{port_info['port']:<7}"
                f"{port_info['service']:<10}"
                f"{banner}"
            )

    print("\nVULNERABILITIES")
    print("-" * 48)

    if not findings:
        print("No known vulnerabilities detected.")
    else:
        for finding in findings:
            print(f"[{finding.severity}] {finding.cve}")
            print(f"Port:        {finding.port}")
            print(f"Service:     {finding.service}")
            print(f"Version:     {finding.version}")
            print(f"Description: {finding.description}")
            print()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for finding in findings:
        severity = finding.severity.upper()

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["UNKNOWN"] += 1

    print("SCAN SUMMARY")
    print("-" * 48)
    print(f"Open ports:          {len(open_ports)}")
    print(f"Vulnerabilities:     {len(findings)}")
    print(f"Critical:            {severity_counts['CRITICAL']}")
    print(f"High:                {severity_counts['HIGH']}")
    print(f"Medium:              {severity_counts['MEDIUM']}")
    print(f"Low:                 {severity_counts['LOW']}")
    print(f"Unknown:              {severity_counts['UNKNOWN']}")


def generate_json_report(
    target: str,
    ports_scanned: int,
    open_ports: list[dict],
    findings: list[Finding],
) -> dict:

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["unknown"] += 1

    return {
        "target": target,
        "ports_scanned": ports_scanned,
        "open_ports": open_ports,
        "findings": [asdict(finding) for finding in findings],
        "summary": severity_counts,
    }


def save_json_report(report: dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"\n[+] JSON report saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lightweight TCP vulnerability scanner"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="IP address or hostname to scan",
    )

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Ports to scan. Examples: 1-1024 or 22,80,443",
    )

    parser.add_argument(
        "--output",
        help="Optional path for JSON report",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent scanning workers",
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    if args.workers < 1:
        parser.error("Workers must be greater than 0")

    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        parser.error(f"Unable to resolve target: {args.target}")

    vuln_db = load_vuln_db()

    print(f"[+] Target: {args.target}")
    print(f"[+] Scanning {len(ports)} ports...")
    print()

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_port, args.target, port): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()

            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])

    findings = []

    for port_info in open_ports:
        findings.extend(
            match_vulnerabilities(
                args.target,
                port_info,
                vuln_db,
            )
        )

    print_scan_results(
        args.target,
        open_ports,
        findings,
        len(ports),
    )

    if args.output:
        report = generate_json_report(
            args.target,
            len(ports),
            open_ports,
            findings,
        )

        save_json_report(report, args.output)


if __name__ == "__main__":
    main()