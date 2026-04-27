# IT-Solutions Netzwerkcheck

Der IT-Solutions Netzwerkcheck ist ein lokales Open-Source-Tool für Windows zur einfachen Überprüfung aktiv sichtbarer Geräte und offener Standarddienste im eigenen Netzwerk.

Das Tool wurde von Lucas Biesenberger IT-Solutions entwickelt und dient als erste Orientierung für grundlegende Netzwerk- und Sicherheitsrisiken.

## Was das Tool macht

Die Version 1.2.3 enthält eine modernisierte Oberfläche im IT-Solutions Branding mit Dashboard, Ergebnisliste und Risikoübersicht.


- erkennt aktiv erreichbare bzw. lokal sichtbare Geräte im Netzwerk
- prüft ausgewählte Standardports
- erkennt offene Dienste wie HTTP, HTTPS, SMB, RDP, FTP, Telnet oder VNC
- liest zusätzlich die lokale ARP-Tabelle aus
- zeigt MAC-Adressen an, sofern lokal verfügbar
- bewertet gefundene Hinweise grob nach niedrig, mittel und hoch
- erzeugt einen verständlichen HTML-Bericht
- erzeugt zusätzlich einen JSON-Bericht zur technischen Auswertung
- weist darauf hin, wenn Hostnamen und offene Dienste unplausibel wirken können

## Was das Tool nicht macht

- keine Angriffe auf Systeme
- keine Passworttests
- keine Exploits
- keine Umgehung von Schutzmaßnahmen
- keine Änderungen an Geräten oder Einstellungen
- keine Installation von Hintergrunddiensten
- keine vollständige Inventarisierung aller Geräte
- keine Schwachstellenprüfung nach CVE-Datenbank

## Wichtiger Hinweis zur Geräteerkennung

Der Netzwerkcheck zeigt aktiv sichtbare Geräte zum Zeitpunkt des Scans.

Die Anzahl kann von der Geräteliste eines Routers abweichen, da Router oft auch alte, offline befindliche oder schlafende Geräte anzeigen. Manche Geräte blockieren Ping, haben keine offenen Standarddienste oder befinden sich in einem anderen Netz, Gastnetz oder VLAN.

Hostnamen können aus Router- oder DNS-Caches stammen und sind nicht immer eindeutig. Deshalb sollten auffällige Ergebnisse bei Bedarf manuell mit Router, Geräteliste oder Inventar abgeglichen werden.

## Rechtlicher Hinweis

Der IT-Solutions Netzwerkcheck darf nur in Netzwerken ausgeführt werden, für die eine ausdrückliche Berechtigung besteht.

Die Nutzung in fremden Netzwerken ohne Zustimmung ist nicht erlaubt.

## Download für Windows

Die aktuelle Windows-Version kann über die GitHub Releases heruntergeladen werden:

```text
https://github.com/Biesenbergerit/IT-Solutions-Netzwerkcheck/releases/latest
```

Hinweis: Da es sich um ein neues Windows-Tool handelt, kann Windows SmartScreen beim ersten Start eine Sicherheitswarnung anzeigen. Der Quellcode ist öffentlich einsehbar.

## Bedienung

1. Netzwerkcheck herunterladen.
2. Datei per Doppelklick starten.
3. Bestätigen, dass Sie berechtigt sind, das Netzwerk zu prüfen.
4. Den automatisch erkannten Netzwerkbereich prüfen.
5. Auf „Scan starten“ klicken.
6. Nach Abschluss den erzeugten HTML-Bericht öffnen.

## Start als Python-Skript

Voraussetzung: Python 3.11 oder neuer.

```bash
python netzwerkcheck.py
```

CLI-Modus:

```bash
python netzwerkcheck.py --network 192.168.178.0/24 --cli
```

## Windows EXE selbst bauen

Mit PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name IT-Solutions-Netzwerkcheck netzwerkcheck.py
```

Die fertige EXE liegt danach unter:

```text
dist/IT-Solutions-Netzwerkcheck.exe
```

Alternativ kann unter Windows die Datei `build_windows.bat` verwendet werden.

## Automatischer Build über GitHub Actions

Dieses Repository enthält einen GitHub Actions Workflow, der automatisch eine Windows-EXE erzeugen kann.

Workflow-Datei:

```text
.github/workflows/build-windows-exe.yml
```

Nach einem erfolgreichen Build kann das erzeugte Artefakt heruntergeladen und als GitHub Release veröffentlicht werden.

## Empfohlener Einsatz

Der Netzwerkcheck eignet sich als erste technische Orientierung für:

- kleine Unternehmen
- Handwerksbetriebe
- Arztpraxen
- Kanzleien
- lokale Firmennetzwerke
- interne IT-Prüfungen

Der Bericht ersetzt keine vollständige professionelle Sicherheitsanalyse, kann aber helfen, offensichtliche Risiken frühzeitig zu erkennen.

## Roadmap

Geplante oder mögliche Erweiterungen:

- PDF-Bericht
- optionaler Ergebnisexport
- bessere Geräteerkennung über weitere Quellen
- Code-Signing
- Microsoft 365 Check als separates Modul
- optionales Admin-Dashboard für Auswertungen

## Lizenz

Dieses Projekt steht unter der MIT License.
