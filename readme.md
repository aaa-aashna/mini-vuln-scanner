import json

import pytest

from scanner import (
    Finding,
    generate_json_report,
    load_vuln_db,
    match_vulnerabilities,
    parse_ports,
)


def test_parse_single_port():
    assert parse_ports("80") == [80]


def test_parse_port_range():
    assert parse_ports("80-82") == [80, 81, 82]


def test_parse_multiple_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_mixed_ports():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]


def test_invalid_port():
    with pytest.raises(ValueError):
        parse_ports("70000")


def test_invalid_port_range():
    with pytest.raises(ValueError):
        parse_ports("100-50")


def test_load_vulnerability_database(tmp_path):
    database = {
        "http": {
            "Apache 2.4.49": {
                "cve": "CVE-2021-41773",
                "severity": "CRITICAL",
                "description": "Path traversal vulnerability",
            }
        }
    }

    database_path = tmp_path / "vuln_db.json"

    with open(database_path, "w", encoding="utf-8") as file:
        json.dump(database, file)

    result = load_vuln_db(str(database_path))

    assert result == database


def test_match_vulnerability():
    vuln_db = {
        "http": {
            "Apache 2.4.49": {
                "cve": "CVE-2021-41773",
                "severity": "CRITICAL",
                "description": "Path traversal vulnerability",
            }
        }
    }

    port_info = {
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "banner": "Apache 2.4.49",
    }

    findings = match_vulnerabilities(
        "127.0.0.1",
        port_info,
        vuln_db,
    )

    assert len(findings) == 1
    assert findings[0].cve == "CVE-2021-41773"
    assert findings[0].severity == "CRITICAL"


def test_no_vulnerability_match():
    vuln_db = {
        "http": {
            "Apache 2.4.49": {
                "cve": "CVE-2021-41773",
                "severity": "CRITICAL",
                "description": "Path traversal vulnerability",
            }
        }
    }

    port_info = {
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "banner": "Apache 2.4.60",
    }

    findings = match_vulnerabilities(
        "127.0.0.1",
        port_info,
        vuln_db,
    )

    assert findings == []


def test_json_report():
    finding = Finding(
        target="127.0.0.1",
        port=80,
        protocol="tcp",
        service="http",
        version="Apache 2.4.49",
        cve="CVE-2021-41773",
        severity="CRITICAL",
        description="Path traversal vulnerability",
    )

    report = generate_json_report(
        "127.0.0.1",
        1024,
        [
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "banner": "Apache 2.4.49",
            }
        ],
        [finding],
    )

    assert report["target"] == "127.0.0.1"
    assert report["ports_scanned"] == 1024
    assert len(report["findings"]) == 1
    assert report["summary"]["critical"] == 1