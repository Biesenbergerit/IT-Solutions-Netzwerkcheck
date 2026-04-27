"""
IT-Solutions Netzwerkcheck
Version: 1.1.0
Autor: IT-Solutions / Lucas Biesenberger

Zweck:
- Lokaler Netzwerkcheck für berechtigte Netzwerke
- Erkennt aktiv erreichbare Geräte und offene Standardports
- Nutzt zusätzlich ARP-Informationen für bessere Geräteerkennung
- Erzeugt JSON- und HTML-Bericht
- Führt keine Exploits, Passworttests oder Umgehungen durch

Start:
    python netzwerkcheck.py

Optional CLI:
    python netzwerkcheck.py --network 192.168.178.0/24 --cli
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import datetime as dt
import html
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import tkinter as tk
from dataclasses import dataclass, asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

COMMON_PORTS = {
    21: ("FTP", "hoch", "FTP erkannt. Falls dieser Dienst nicht bewusst genutzt wird, sollte er deaktiviert oder durch eine verschlüsselte Alternative ersetzt werden."),
    22: ("SSH", "mittel", "SSH ist legitim, sollte aber nur mit starken Zugangsdaten, Updates und eingeschränktem Zugriff betrieben werden."),
    23: ("Telnet", "hoch", "Telnet ist unverschlüsselt und sollte deaktiviert oder ersetzt werden."),
    25: ("SMTP", "mittel", "Maildienste sollten sauber abgesichert und nicht offen relayfähig sein."),
    53: ("DNS", "niedrig", "DNS kann legitim sein, sollte aber nicht unnötig offen sein."),
    80: ("HTTP", "niedrig", "Weboberfläche gefunden. Prüfen, ob Login, Updates und Zugriffsschutz sicher sind."),
    110: ("POP3", "mittel", "POP3 sollte möglichst verschlüsselt genutzt werden."),
    139: ("NetBIOS", "mittel", "Alter Windows-Dateifreigabedienst. In Firmennetzen kritisch prüfen."),
    143: ("IMAP", "mittel", "IMAP sollte möglichst verschlüsselt genutzt werden."),
    443: ("HTTPS", "niedrig", "HTTPS-Weboberfläche gefunden. Zertifikat, Login und Updates prüfen."),
    445: ("SMB", "mittel", "Windows-Dateifreigabe. Nur intern nutzen, Updates, Freigaben und Rechte prüfen."),
    587: ("SMTP Submission", "niedrig", "Mailversanddienst gefunden. Authentifizierung und Verschlüsselung prüfen."),
    993: ("IMAPS", "niedrig", "Verschlüsselter Mailzugriff gefunden."),
    995: ("POP3S", "niedrig", "Verschlüsselter Mailzugriff gefunden."),
    1433: ("Microsoft SQL Server", "hoch", "Datenbankdienst gefunden. Zugriff stark einschränken und Absicherung prüfen."),
    3306: ("MySQL/MariaDB", "hoch", "Datenbankdienst gefunden. Zugriff stark einschränken und Absicherung prüfen."),
    3389: ("RDP", "hoch", "Remote Desktop gefunden. Starke Absicherung und kein direkter Internetzugriff empfohlen."),
    5432: ("PostgreSQL", "hoch", "Datenbankdienst gefunden. Zugriff stark einschränken und Absicherung prüfen."),
    5900: ("VNC", "hoch", "Fernwartungsdienst gefunden. Stark absichern oder deaktivieren."),
    8080: ("HTTP Alternate/Admin", "mittel", "Mögliche Admin-Weboberfläche gefunden. Zugriff und Updates prüfen."),
    8443: ("HTTPS Alternate/Admin", "mittel", "Mögliche Admin-Weboberfläche gefunden. Zugriff und Updates prüfen."),
}

RISK_POINTS = {
    "niedrig": 5,
    "mittel": 15,
    "hoch": 30,
}


@dataclass
class PortResult:
    port: int
    service: str
    risk: str
    recommendation: str


@dataclass
class HostResult:
    ip: str
    hostname: str | None
    mac_address: str | None
    open_ports: list[PortResult]
    risk_score: int
    detection_sources: list[str]
    notes: list[str]


def get_default_output_dir() -> Path:
    path = Path.home() / "Documents" / "IT-Solutions-Netzwerkcheck"
    path.mkdir(parents=True, exist_ok=True)
    return path


def guess_local_network() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(f"{ip}/24", strict=False).with_prefixlen)
    except Exception:
        return "192.168.178.0/24"


def ping_host(ip: str, timeout_seconds: float = 0.8) -> bool:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_seconds * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), ip]

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds + 0.5,
        )
        return completed.returncode == 0
    except Exception:
        return False


def check_port(ip: str, port: int, timeout_seconds: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def parse_arp_table() -> dict[str, str]:
    """
    Liest die lokale ARP-Tabelle aus.

    Wichtig:
    ARP zeigt nur Geräte im gleichen lokalen Layer-2-Netz.
    ARP ist eine Momentaufnahme und keine vollständige Inventarisierung.
    """
    result: dict[str, str] = {}

    try:
        completed = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=5,
        )
        output = completed.stdout + "\n" + completed.stderr

        pattern = re.compile(
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}).*?(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
        )

        for match in pattern.finditer(output):
            ip = match.group("ip")
            mac = match.group("mac").replace("-", ":").lower()
            result[ip] = mac
    except Exception:
        pass

    return result


def calculate_host_score(open_ports: list[PortResult]) -> int:
    score = sum(RISK_POINTS.get(p.risk, 0) for p in open_ports)
    return min(score, 100)


def get_host_notes(
    ip: str,
    hostname: str | None,
    mac_address: str | None,
    open_ports: list[PortResult],
    detection_sources: list[str],
) -> list[str]:
    notes: list[str] = []

    if hostname:
        notes.append("Hostname stammt aus Reverse-DNS bzw. Router/DNS-Cache und muss nicht immer eindeutig sein.")

    if mac_address:
        notes.append("MAC-Adresse wurde aus der lokalen ARP-Tabelle gelesen. ARP-Daten sind nur eine Momentaufnahme.")

    if not open_ports:
        notes.append("Gerät wurde erkannt, aber auf den geprüften Standardports wurden keine offenen Dienste gefunden.")

    risky_ports = {p.port for p in open_ports if p.risk in ("hoch", "mittel")}
    hostname_l = (hostname or "").lower()

    iot_keywords = [
        "echo", "alexa", "amazon", "tv", "chromecast", "homepod", "speaker",
        "drucker", "printer", "kamera", "camera", "thermostat", "ring",
        "smart", "bulb", "light", "sonos",
    ]

    if hostname_l and any(k in hostname_l for k in iot_keywords) and risky_ports.intersection(
        {21, 23, 139, 445, 3389, 5900, 1433, 3306, 5432}
    ):
        notes.append(
            "Hostname und offene Dienste wirken möglicherweise unplausibel. Bitte Gerät manuell prüfen, da Router/DNS-Caches alte Namen anzeigen können."
        )

    return notes


def scan_host(ip: str, ports: dict[int, tuple[str, str, str]], port_timeout: float) -> HostResult | None:
    detection_sources: list[str] = []
    alive = ping_host(ip)

    if alive:
        detection_sources.append("Ping")

    open_ports: list[PortResult] = []
    for port, (service, risk, recommendation) in ports.items():
        if check_port(ip, port, timeout_seconds=port_timeout):
            open_ports.append(PortResult(port, service, risk, recommendation))

    if open_ports:
        detection_sources.append("Offene Ports")

    if not alive and not open_ports:
        return None

    hostname = reverse_dns(ip)
    return HostResult(
        ip=ip,
        hostname=hostname,
        mac_address=None,
        open_ports=open_ports,
        risk_score=calculate_host_score(open_ports),
        detection_sources=detection_sources,
        notes=[],
    )


def enrich_with_arp_and_notes(results: list[HostResult], network: ipaddress._BaseNetwork) -> list[HostResult]:
    arp = parse_arp_table()
    by_ip = {h.ip: h for h in results}

    for ip, mac in arp.items():
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except Exception:
            continue

        if ip in by_ip:
            by_ip[ip].mac_address = mac
            if "ARP" not in by_ip[ip].detection_sources:
                by_ip[ip].detection_sources.append("ARP")
        else:
            hostname = reverse_dns(ip)
            host = HostResult(
                ip=ip,
                hostname=hostname,
                mac_address=mac,
                open_ports=[],
                risk_score=0,
                detection_sources=["ARP"],
                notes=[],
            )
            by_ip[ip] = host

    for host in by_ip.values():
        host.notes = get_host_notes(
            host.ip,
            host.hostname,
            host.mac_address,
            host.open_ports,
            host.detection_sources,
        )

    return list(by_ip.values())


def scan_network(
    network_cidr: str,
    max_workers: int = 80,
    port_timeout: float = 0.5,
    progress_callback=None,
) -> dict:
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    started = dt.datetime.now()

    results: list[HostResult] = []
    checked = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(scan_host, ip, COMMON_PORTS, port_timeout): ip
            for ip in hosts
        }

        for future in concurrent.futures.as_completed(future_map):
            checked += 1
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass

            if progress_callback:
                progress_callback(checked, len(hosts), len(results))

    results = enrich_with_arp_and_notes(results, network)

    finished = dt.datetime.now()
    overall_score = calculate_overall_score(results)
    sorted_results = sorted(results, key=lambda x: ipaddress.ip_address(x.ip))

    return {
        "scanner": "IT-Solutions Netzwerkcheck",
        "version": "1.1.0",
        "network": str(network.with_prefixlen),
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 2),
        "overall_risk_score": overall_score,
        "summary": {
            "active_hosts_found": len(sorted_results),
            "hosts_with_open_ports": sum(1 for h in sorted_results if h.open_ports),
            "arp_only_hosts": sum(1 for h in sorted_results if h.detection_sources == ["ARP"]),
            "open_ports_total": sum(len(h.open_ports) for h in sorted_results),
            "high_risk_findings": sum(1 for h in sorted_results for p in h.open_ports if p.risk == "hoch"),
            "medium_risk_findings": sum(1 for h in sorted_results for p in h.open_ports if p.risk == "mittel"),
            "low_risk_findings": sum(1 for h in sorted_results for p in h.open_ports if p.risk == "niedrig"),
        },
        "results": [host_to_dict(h) for h in sorted_results],
        "legal_notice": (
            "Dieser Check darf nur in Netzwerken ausgeführt werden, für die eine ausdrückliche Berechtigung besteht. "
            "Das Tool führt keine Exploits, keine Passworttests und keine Umgehung von Schutzmaßnahmen durch."
        ),
        "accuracy_notice": (
            "Die gefundenen Geräte sind aktiv erreichbare bzw. lokal sichtbare Geräte zum Zeitpunkt des Scans. "
            "Die Anzahl kann von Router-Listen abweichen, da Router oft auch alte, offline befindliche oder schlafende Geräte anzeigen. "
            "Hostnamen können aus DNS- oder Router-Caches stammen und sind nicht immer eindeutig."
        ),
    }


def host_to_dict(host: HostResult) -> dict:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "mac_address": host.mac_address,
        "risk_score": host.risk_score,
        "detection_sources": host.detection_sources,
        "notes": host.notes,
        "open_ports": [asdict(p) for p in host.open_ports],
    }


def calculate_overall_score(hosts: list[HostResult]) -> int:
    if not hosts:
        return 0

    high = sum(1 for h in hosts for p in h.open_ports if p.risk == "hoch")
    medium = sum(1 for h in hosts for p in h.open_ports if p.risk == "mittel")
    low = sum(1 for h in hosts for p in h.open_ports if p.risk == "niedrig")
    exposed_hosts = sum(1 for h in hosts if h.open_ports)

    score = high * 18 + medium * 8 + low * 2 + exposed_hosts * 3
    return min(score, 100)


def risk_label(score: int) -> str:
    if score >= 70:
        return "Hoch"
    if score >= 35:
        return "Mittel"
    if score > 0:
        return "Niedrig"
    return "Keine Auffälligkeiten"


def save_json(report: dict, output_dir: Path) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"netzwerkcheck_{timestamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def save_html(report: dict, output_dir: Path) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"netzwerkcheck_{timestamp}.html"
    path.write_text(render_html_report(report), encoding="utf-8")
    return path


def render_html_report(report: dict) -> str:
    score = int(report.get("overall_risk_score", 0))
    label = risk_label(score)
    summary = report.get("summary", {})

    rows = []
    for host in report.get("results", []):
        ports = host.get("open_ports", [])
        sources = ", ".join(host.get("detection_sources", [])) or "-"
        notes = host.get("notes", [])

        if not ports:
            port_html = "<em>Keine offenen Standardports erkannt</em>"
        else:
            port_html = "<ul>" + "".join(
                f"<li><strong>{p['port']} {html.escape(p['service'])}</strong> "
                f"<span class='risk {p['risk']}'>{html.escape(p['risk'])}</span><br>"
                f"{html.escape(p['recommendation'])}</li>"
                for p in ports
            ) + "</ul>"

        notes_html = ""
        if notes:
            notes_html = "<ul class='notes'>" + "".join(
                f"<li>{html.escape(note)}</li>" for note in notes
            ) + "</ul>"

        rows.append(
            f"""
            <tr>
                <td>{html.escape(host.get("ip", ""))}</td>
                <td>{html.escape(host.get("hostname") or "-")}</td>
                <td>{html.escape(host.get("mac_address") or "-")}</td>
                <td>{html.escape(sources)}</td>
                <td>{host.get("risk_score", 0)}</td>
                <td>{port_html}{notes_html}</td>
            </tr>
            """
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='6'>Keine Geräte gefunden.</td></tr>"

    return f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>IT-Solutions Netzwerkcheck Bericht</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
    body {{
        font-family: Arial, sans-serif;
        margin: 0;
        background: #f4f6f8;
        color: #1f2937;
    }}
    .container {{
        max-width: 1200px;
        margin: 0 auto;
        padding: 32px 20px;
    }}
    .card {{
        background: #ffffff;
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    }}
    h1, h2 {{
        margin-top: 0;
    }}
    .score {{
        font-size: 44px;
        font-weight: 700;
        margin: 8px 0;
    }}
    .pill {{
        display: inline-block;
        padding: 6px 12px;
        border-radius: 999px;
        background: #e5e7eb;
        font-weight: 700;
    }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
    }}
    .metric {{
        background: #f9fafb;
        border-radius: 12px;
        padding: 16px;
    }}
    .metric strong {{
        display: block;
        font-size: 26px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: #fff;
    }}
    th, td {{
        text-align: left;
        vertical-align: top;
        padding: 12px;
        border-bottom: 1px solid #e5e7eb;
    }}
    th {{
        background: #f9fafb;
    }}
    .risk {{
        display: inline-block;
        margin-left: 8px;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 700;
    }}
    .risk.hoch {{
        background: #fee2e2;
    }}
    .risk.mittel {{
        background: #fef3c7;
    }}
    .risk.niedrig {{
        background: #dcfce7;
    }}
    .note, .notes {{
        font-size: 13px;
        color: #6b7280;
    }}
    .notes {{
        margin-top: 10px;
        padding-left: 18px;
    }}
    .callout {{
        background: #eef6ff;
        border: 1px solid #bfdbfe;
        border-radius: 12px;
        padding: 16px;
        color: #1e3a8a;
    }}
    @media (max-width: 900px) {{
        .grid {{
            grid-template-columns: 1fr 1fr;
        }}
        table, thead, tbody, th, td, tr {{
            display: block;
        }}
        th {{
            display: none;
        }}
        td {{
            border-bottom: none;
            padding: 8px 12px;
        }}
        tr {{
            border-bottom: 1px solid #e5e7eb;
            padding: 12px 0;
        }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>IT-Solutions Netzwerkcheck</h1>
        <p>Bericht für Netzwerk: <strong>{html.escape(report.get("network", "-"))}</strong></p>
        <p>Zeitraum: {html.escape(report.get("started_at", "-"))} bis {html.escape(report.get("finished_at", "-"))}</p>
        <div class="score">{score}/100</div>
        <span class="pill">Risiko: {html.escape(label)}</span>
    </div>

    <div class="card">
        <h2>Zusammenfassung</h2>
        <div class="grid">
            <div class="metric"><strong>{summary.get("active_hosts_found", 0)}</strong> aktiv sichtbare Geräte</div>
            <div class="metric"><strong>{summary.get("hosts_with_open_ports", 0)}</strong> Geräte mit offenen Diensten</div>
            <div class="metric"><strong>{summary.get("high_risk_findings", 0)}</strong> hohe Risiken</div>
            <div class="metric"><strong>{summary.get("medium_risk_findings", 0)}</strong> mittlere Risiken</div>
        </div>
    </div>

    <div class="card callout">
        <h2>Hinweis zur Genauigkeit</h2>
        <p>{html.escape(report.get("accuracy_notice", ""))}</p>
    </div>

    <div class="card">
        <h2>Gefundene aktiv sichtbare Geräte und Dienste</h2>
        <table>
            <thead>
                <tr>
                    <th>IP-Adresse</th>
                    <th>Hostname</th>
                    <th>MAC-Adresse</th>
                    <th>Erkannt durch</th>
                    <th>Score</th>
                    <th>Offene Dienste & Hinweise</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Empfohlene nächste Schritte</h2>
        <ol>
            <li>Hohe Risiken priorisiert prüfen, insbesondere Telnet, FTP, RDP, VNC und Datenbankdienste.</li>
            <li>Unnötige Dienste deaktivieren oder per Firewall einschränken.</li>
            <li>Hostnamen mit Router- oder Geräteliste abgleichen, wenn Dienste unplausibel wirken.</li>
            <li>Backups, Updates, Benutzerrechte und Fernzugriffe kontrollieren.</li>
            <li>Für geschäftliche Netzwerke eine regelmäßige IT-Betreuung und Monitoring einführen.</li>
        </ol>
        <p><strong>IT-Solutions</strong><br>
        Höhenblick 2, 88521 Ertingen<br>
        Telefon: +49 162 3971934<br>
        E-Mail: info@biesenbergerit.de</p>
        <p class="note">{html.escape(report.get("legal_notice", ""))}</p>
    </div>
</div>
</body>
</html>
"""


class NetworkCheckApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("IT-Solutions Netzwerkcheck")
        self.root.geometry("820x590")
        self.root.minsize(760, 540)

        self.is_scanning = False
        self.output_dir = get_default_output_dir()

        self.network_var = tk.StringVar(value=guess_local_network())
        self.status_var = tk.StringVar(value="Bereit.")
        self.consent_var = tk.BooleanVar(value=False)
        self.progress_var = tk.DoubleVar(value=0)

        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 16, "pady": 8}

        title = ttk.Label(
            self.root,
            text="IT-Solutions Netzwerkcheck",
            font=("Segoe UI", 20, "bold"),
        )
        title.pack(anchor="w", **padding)

        subtitle = ttk.Label(
            self.root,
            text="Lokaler Sicherheitscheck für aktiv sichtbare Geräte, ARP-Informationen und offene Standarddienste.",
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor="w", **padding)

        info = ttk.Label(
            self.root,
            text="Hinweis: Router zeigen oft auch alte, offline befindliche oder schlafende Geräte. Dieser Check zeigt aktiv sichtbare Geräte zum Zeitpunkt des Scans.",
            font=("Segoe UI", 9),
            foreground="#555555",
            wraplength=740,
        )
        info.pack(anchor="w", **padding)

        frame = ttk.Frame(self.root)
        frame.pack(fill="x", **padding)

        ttk.Label(frame, text="Netzwerkbereich CIDR:").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(frame, textvariable=self.network_var, width=32)
        entry.grid(row=0, column=1, sticky="w", padx=(12, 8))

        ttk.Button(frame, text="Automatisch erkennen", command=self.autodetect).grid(row=0, column=2, sticky="w")

        consent = ttk.Checkbutton(
            self.root,
            text="Ich bestätige, dass ich berechtigt bin, dieses Netzwerk zu prüfen.",
            variable=self.consent_var,
        )
        consent.pack(anchor="w", **padding)

        actions = ttk.Frame(self.root)
        actions.pack(fill="x", **padding)

        self.start_button = ttk.Button(actions, text="Scan starten", command=self.start_scan)
        self.start_button.pack(side="left")

        ttk.Button(actions, text="Ausgabeordner wählen", command=self.choose_output_dir).pack(side="left", padx=8)
        ttk.Button(actions, text="Ordner öffnen", command=self.open_output_dir).pack(side="left")

        self.progress = ttk.Progressbar(
            self.root,
            variable=self.progress_var,
            maximum=100,
            mode="determinate",
        )
        self.progress.pack(fill="x", **padding)

        ttk.Label(self.root, textvariable=self.status_var).pack(anchor="w", **padding)

        self.text = tk.Text(self.root, height=16, wrap="word")
        self.text.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        self.text.insert("end", "Version 1.1.0\n")
        self.text.insert("end", "Hinweis: Dieses Tool ist für berechtigte Prüfungen im eigenen Netzwerk gedacht.\n")
        self.text.insert("end", "Neu: ARP-Auswertung, Hinweise zu DNS-Cache und bessere Berichtserklärung.\n")
        self.text.configure(state="disabled")

    def log(self, message: str):
        self.text.configure(state="normal")
        self.text.insert("end", f"{message}\n")
        self.text.see("end")
        self.text.configure(state="disabled")

    def autodetect(self):
        self.network_var.set(guess_local_network())

    def choose_output_dir(self):
        selected = filedialog.askdirectory(initialdir=str(self.output_dir))
        if selected:
            self.output_dir = Path(selected)
            self.log(f"Ausgabeordner gesetzt: {self.output_dir}")

    def open_output_dir(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if platform.system().lower().startswith("win"):
            os.startfile(self.output_dir)  # type: ignore[attr-defined]
        elif platform.system().lower() == "darwin":
            subprocess.run(["open", str(self.output_dir)])
        else:
            subprocess.run(["xdg-open", str(self.output_dir)])

    def start_scan(self):
        if self.is_scanning:
            return

        if not self.consent_var.get():
            messagebox.showwarning(
                "Zustimmung erforderlich",
                "Bitte bestätigen Sie zuerst, dass Sie berechtigt sind, dieses Netzwerk zu prüfen.",
            )
            return

        network = self.network_var.get().strip()
        try:
            parsed = ipaddress.ip_network(network, strict=False)
            network = str(parsed.with_prefixlen)
            self.network_var.set(network)
            if parsed.num_addresses > 1024:
                ok = messagebox.askyesno(
                    "Großer Scanbereich",
                    "Der angegebene Bereich enthält mehr als 1024 Adressen. Fortfahren?"
                )
                if not ok:
                    return
        except Exception:
            messagebox.showerror("Ungültiges Netzwerk", "Bitte geben Sie einen gültigen CIDR-Bereich an, z. B. 192.168.178.0/24.")
            return

        self.is_scanning = True
        self.start_button.configure(state="disabled")
        self.progress_var.set(0)
        self.status_var.set("Scan läuft...")
        self.log(f"Starte Scan für {network}")

        thread = threading.Thread(target=self._scan_worker, args=(network,), daemon=True)
        thread.start()

    def _scan_worker(self, network: str):
        def progress_callback(done, total, found):
            percent = (done / total) * 100 if total else 0
            self.root.after(0, lambda: self.progress_var.set(percent))
            self.root.after(0, lambda: self.status_var.set(f"Prüfe Geräte: {done}/{total}, aktiv sichtbar: {found}"))

        try:
            report = scan_network(network, progress_callback=progress_callback)
            json_path = save_json(report, self.output_dir)
            html_path = save_html(report, self.output_dir)

            def finish():
                self.log("Scan abgeschlossen.")
                self.log(f"JSON-Bericht: {json_path}")
                self.log(f"HTML-Bericht: {html_path}")
                self.status_var.set(
                    f"Fertig. Aktiv sichtbare Geräte: {report['summary']['active_hosts_found']}, Risiko: {risk_label(report['overall_risk_score'])}"
                )
                messagebox.showinfo(
                    "Scan abgeschlossen",
                    f"Bericht erstellt:\n\n{html_path}"
                )
        except Exception as exc:
            def finish():
                self.log(f"Fehler: {exc}")
                self.status_var.set("Fehler beim Scan.")
                messagebox.showerror("Fehler", str(exc))
        finally:
            def reset():
                self.is_scanning = False
                self.start_button.configure(state="normal")
            self.root.after(0, finish)
            self.root.after(0, reset)


_APP_MUTEX_HANDLE = None


def acquire_single_instance_lock() -> bool:
    global _APP_MUTEX_HANDLE

    if not platform.system().lower().startswith("win"):
        return True

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _APP_MUTEX_HANDLE = kernel32.CreateMutexW(None, False, "Global\\IT_Solutions_Netzwerkcheck_SingleInstance")
        already_exists = ctypes.get_last_error() == 183
        return not already_exists
    except Exception:
        return True


def run_gui():
    root = tk.Tk()
    NetworkCheckApp(root)
    root.mainloop()


def run_cli(network: str):
    print(f"Starte Netzwerkcheck für {network}")
    report = scan_network(network)
    output_dir = get_default_output_dir()
    json_path = save_json(report, output_dir)
    html_path = save_html(report, output_dir)
    print("Fertig.")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(f"Risiko: {risk_label(report['overall_risk_score'])} ({report['overall_risk_score']}/100)")
    print(f"Aktiv sichtbare Geräte: {report['summary']['active_hosts_found']}")


def main():
    parser = argparse.ArgumentParser(description="IT-Solutions Netzwerkcheck")
    parser.add_argument("--network", default=guess_local_network(), help="CIDR-Netzwerk, z. B. 192.168.178.0/24")
    parser.add_argument("--cli", action="store_true", help="Ohne GUI starten")
    args = parser.parse_args()

    if args.cli:
        run_cli(args.network)
    else:
        if not acquire_single_instance_lock():
            messagebox.showinfo(
                "IT-Solutions Netzwerkcheck läuft bereits",
                "Der Netzwerkcheck ist bereits geöffnet. Bitte verwenden Sie das vorhandene Fenster."
            )
            return
        run_gui()


if __name__ == "__main__":
    main()
