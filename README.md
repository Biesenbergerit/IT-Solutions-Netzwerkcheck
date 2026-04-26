# IT-Solutions Netzwerkcheck MVP

Lokales Windows-Tool für einen einfachen Netzwerk-Sicherheitscheck.

## Was das Tool macht

- erkennt erreichbare Geräte im lokalen Netzwerk
- prüft ausgewählte Standardports
- bewertet Risiken grob nach niedrig, mittel, hoch
- erzeugt JSON- und HTML-Berichte
- führt keine Exploits, keine Passworttests und keine Umgehung von Schutzmaßnahmen durch

## Rechtlicher Hinweis

Das Tool darf nur in Netzwerken ausgeführt werden, für die eine ausdrückliche Berechtigung besteht.

## Start als Python-Skript

Voraussetzung: Python 3.11 oder neuer.

```bash
python netzwerkcheck.py
```

CLI-Modus:

```bash
python netzwerkcheck.py --network 192.168.178.0/24 --cli
```

## Windows EXE bauen

1. Python installieren
2. Im Projektordner ausführen:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name IT-Solutions-Netzwerkcheck netzwerkcheck.py
```

Die fertige EXE liegt danach unter:

```text
dist/IT-Solutions-Netzwerkcheck.exe
```

Alternativ die Datei `build_windows.bat` doppelklicken.

## Empfohlener Website-Ablauf

1. Landingpage: Kostenloser IT-Sicherheitscheck
2. Download-Button für die EXE
3. Kunde bestätigt Berechtigung im Tool
4. Tool erzeugt HTML-Bericht
5. Kunde sendet den Bericht freiwillig an IT-Solutions oder bucht eine Auswertung

## Sinnvolle nächste Erweiterungen

- digitales Formular vor dem Scan mit Firmenname und E-Mail
- Bericht direkt als PDF
- optionaler Upload an dein Backend
- Admin-Dashboard für Leads
- Signierung der EXE mit Code-Signing-Zertifikat
- bessere Geräteerkennung über ARP-Tabelle
- Microsoft 365 Check als separater Cloud-Check
