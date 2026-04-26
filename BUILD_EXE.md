# Windows EXE für Kunden bauen

Wichtig: Der Kunde braucht kein Python.

Python ist nur für dich oder den automatischen Build nötig, um aus `netzwerkcheck.py` eine fertige Windows `.exe` zu erzeugen.

## Variante A: Auf deinem Windows-PC bauen

1. Python von python.org installieren.
2. Beim Installer `Add python.exe to PATH` aktivieren.
3. `build_windows.bat` doppelklicken.
4. Die fertige Kundendatei liegt danach hier:

```text
dist\IT-Solutions-Netzwerkcheck.exe
```

Diese Datei kannst du auf deine Website hochladen.

## Variante B: Ohne lokalen Python-Stress über GitHub Actions bauen

1. Neues privates GitHub Repository erstellen.
2. Projektdateien hochladen.
3. In GitHub auf `Actions` gehen.
4. Workflow `Build Windows EXE` starten.
5. Nach dem Build das Artefakt `IT-Solutions-Netzwerkcheck-Windows` herunterladen.
6. Darin liegt die fertige `.exe`.

Die Workflow-Datei ist enthalten:

```text
.github/workflows/build-windows-exe.yml
```

## Wichtig für professionelle Veröffentlichung

Windows SmartScreen kann bei neuen, unbekannten EXE-Dateien warnen. Das ist normal, wenn die Datei nicht signiert ist.

Für professionellen Einsatz brauchst du später:

- Code-Signing-Zertifikat
- HTTPS-Download von deiner Website
- klare Datenschutzerklärung
- Zustimmung vor dem Scan
- optional eine kurze Anleitung für Kunden
