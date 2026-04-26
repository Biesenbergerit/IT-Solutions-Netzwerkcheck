"""
IT-Solutions Netzwerkcheck MVP
Autor: IT-Solutions / Lucas Biesenberger

Zweck:
- Lokaler Netzwerkcheck für berechtigte Kunden
- Erkennt erreichbare Geräte und offene Standardports
- Erzeugt JSON- und HTML-Bericht
- Führt keine Exploits, Passworttests oder Umgehungen durch

Start:
    python netzwerkcheck.py

Optional CLI:
    python netzwerkcheck.py --network 192.168.178.0/24 --cli
"""

from __future__ import annotations

import argparse
import ctypes
import concurrent.futures
import datetime as dt
import html
import ipaddress
import json
import platform
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from dataclasses import dataclass, asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.request import urlopen
from urllib.error import URLError

COMMON_PORTS = {
    21: ("FTP", "hoch", "FTP überträgt häufig unverschlüsselt. Prüfen, ob der Dienst wirklich benötigt wird."),
    22: ("SSH", "mittel", "SSH ist legitim, sollte aber nur mit starken Zugangsdaten und Updates betrieben werden."),
    23: ("Telnet", "hoch", "Telnet ist unverschlüsselt und sollte deaktiviert oder ersetzt werden."),
    25: ("SMTP", "mittel", "Maildienste sollten sauber abgesichert und nicht offen relayfähig sein."),
    53: ("DNS", "niedrig", "DNS kann legitim sein, sollte aber nicht unnötig offen sein."),
    80: ("HTTP", "niedrig", "Weboberfläche gefunden. Prüfen, ob Login und Updates sicher sind."),
    110: ("POP3", "mittel", "POP3 sollte möglichst verschlüsselt genutzt werden."),
    139: ("NetBIOS", "mittel", "Alter Windows-Dateifreigabedienst. In Firmennetzen kritisch prüfen."),
    143: ("IMAP", "mittel", "IMAP sollte möglichst verschlüsselt genutzt werden."),
    443: ("HTTPS", "niedrig", "HTTPS-Weboberfläche gefunden. Zertifikat und Login prüfen."),
    445: ("SMB", "mittel", "Windows-Dateifreigabe. Nur intern nutzen, Updates und Rechte prüfen."),
    587: ("SMTP Submission", "niedrig", "Mailversanddienst gefunden. Authentifizierung prüfen."),
    993: ("IMAPS", "niedrig", "Verschlüsselter Mailzugriff gefunden."),
    995: ("POP3S", "niedrig", "Verschlüsselter Mailzugriff gefunden."),
    1433: ("Microsoft SQL Server", "hoch", "Datenbankdienst gefunden. Zugriff stark einschränken."),
    3306: ("MySQL/MariaDB", "hoch", "Datenbankdienst gefunden. Zugriff stark einschränken."),
    3389: ("RDP", "hoch", "Remote Desktop gefunden. Starke Absicherung und kein direkter Internetzugriff empfohlen."),
    5432: ("PostgreSQL", "hoch", "Datenbankdienst gefunden. Zugriff stark einschränken."),
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
    open_ports: list[PortResult]
    risk_score: int


def get_default_output_dir() -> Path:
    path = Path.home() / "Documents" / "IT-Solutions-Netzwerkcheck"
    path.mkdir(parents=True, exist_ok=True)
    return path


def guess_local_network() -> str:
    """
    Ermittelt ein wahrscheinliches lokales /24-Netz.
    Beispiel:
    Lokale IP 192.168.0.139 wird zu 192.168.0.0/24.
    """
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
        name = socket.gethostbyaddr(ip)[0]
        return name
    except Exception:
        return None


def calculate_host_score(open_ports: list[PortResult]) -> int:
    score = sum(RISK_POINTS.get(p.risk, 0) for p in open_ports)
    return min(score, 100)


def scan_host(ip: str, ports: dict[int, tuple[str, str, str]], port_timeout: float) -> HostResult | None:
    """
    Prüft Host sehr defensiv:
    - Ping
    - Wenn Ping scheitert, trotzdem kurze Portprüfung auf häufige Ports,
      weil Firewalls Ping blockieren können.
    """
    alive = ping_host(ip)

    open_ports: list[PortResult] = []
    for port, (service, risk, recommendation) in ports.items():
        if check_port(ip, port, timeout_seconds=port_timeout):
            open_ports.append(PortResult(port, service, risk, recommendation))

    if not alive and not open_ports:
        return None

    hostname = reverse_dns(ip)
    return HostResult(
        ip=ip,
        hostname=hostname,
        open_ports=open_ports,
        risk_score=calculate_host_score(open_ports),
    )


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

    finished = dt.datetime.now()

    overall_score = calculate_overall_score(results)

    return {
        "scanner": "IT-Solutions Netzwerkcheck MVP",
        "version": "1.0.1",
        "network": str(network.with_prefixlen),
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 2),
        "overall_risk_score": overall_score,
        "summary": {
            "hosts_found": len(results),
            "open_ports_total": sum(len(h.open_ports) for h in results),
            "high_risk_findings": sum(
                1 for h in results for p in h.open_ports if p.risk == "hoch"
            ),
            "medium_risk_findings": sum(
                1 for h in results for p in h.open_ports if p.risk == "mittel"
            ),
            "low_risk_findings": sum(
                1 for h in results for p in h.open_ports if p.risk == "niedrig"
            ),
        },
        "results": [host_to_dict(h) for h in sorted(results, key=lambda x: ipaddress.ip_address(x.ip))],
        "legal_notice": (
            "Dieser Check darf nur in Netzwerken ausgeführt werden, für die eine ausdrückliche Berechtigung besteht. "
            "Das Tool führt keine Exploits, keine Passworttests und keine Umgehung von Schutzmaßnahmen durch."
        ),
    }


def host_to_dict(host: HostResult) -> dict:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "risk_score": host.risk_score,
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
        if not ports:
            port_html = "<em>Keine offenen Standardports erkannt</em>"
        else:
            port_html = "<ul>" + "".join(
                f"<li><strong>{p['port']} {html.escape(p['service'])}</strong> "
                f"<span class='risk {p['risk']}'>{html.escape(p['risk'])}</span><br>"
                f"{html.escape(p['recommendation'])}</li>"
                for p in ports
            ) + "</ul>"

        rows.append(
            f"""
            <tr>
                <td>{html.escape(host.get("ip", ""))}</td>
                <td>{html.escape(host.get("hostname") or "-")}</td>
                <td>{host.get("risk_score", 0)}</td>
                <td>{port_html}</td>
            </tr>
            """
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='4'>Keine Geräte gefunden.</td></tr>"

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
        max-width: 1100px;
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
    .note {{
        font-size: 13px;
        color: #6b7280;
    }}
    @media (max-width: 800px) {{
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
            <div class="metric"><strong>{summary.get("hosts_found", 0)}</strong> Geräte gefunden</div>
            <div class="metric"><strong>{summary.get("open_ports_total", 0)}</strong> offene Dienste</div>
            <div class="metric"><strong>{summary.get("high_risk_findings", 0)}</strong> hohe Risiken</div>
            <div class="metric"><strong>{summary.get("medium_risk_findings", 0)}</strong> mittlere Risiken</div>
        </div>
    </div>

    <div class="card">
        <h2>Gefundene Geräte und Dienste</h2>
        <table>
            <thead>
                <tr>
                    <th>IP-Adresse</th>
                    <th>Hostname</th>
                    <th>Score</th>
                    <th>Offene Dienste</th>
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
        self.root.geometry("780x560")
        self.root.minsize(720, 520)

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
            text="Lokaler Sicherheitscheck für berechtigte Firmennetzwerke. Keine Exploits, keine Passworttests.",
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor="w", **padding)

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
        self.text.insert("end", "Hinweis: Dieses Tool ist für berechtigte Prüfungen im eigenen Netzwerk gedacht.\n")
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
            self.root.after(0, lambda: self.status_var.set(f"Prüfe Geräte: {done}/{total}, gefunden: {found}"))

        try:
            report = scan_network(network, progress_callback=progress_callback)
            json_path = save_json(report, self.output_dir)
            html_path = save_html(report, self.output_dir)

            def finish():
                self.log(f"Scan abgeschlossen.")
                self.log(f"JSON-Bericht: {json_path}")
                self.log(f"HTML-Bericht: {html_path}")
                self.status_var.set(
                    f"Fertig. Geräte: {report['summary']['hosts_found']}, Risiko: {risk_label(report['overall_risk_score'])}"
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
    """
    Verhindert, dass der Kunde das Tool mehrfach parallel öffnet.
    Besonders wichtig, wenn die EXE versehentlich mehrfach doppelt angeklickt wird.
    """
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
    app = NetworkCheckApp(root)
    root.mainloop()


def run_cli(network: str):
    print(f"Starte Netzwerkcheck für {network}")
    report = scan_network(network)
    output_dir = get_default_output_dir()
    json_path = save_json(report, output_dir)
    html_path = save_html(report, output_dir)
    print(f"Fertig.")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(f"Risiko: {risk_label(report['overall_risk_score'])} ({report['overall_risk_score']}/100)")


def main():
    parser = argparse.ArgumentParser(description="IT-Solutions Netzwerkcheck MVP")
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
