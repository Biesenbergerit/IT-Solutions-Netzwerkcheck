# Änderungen Version 1.2.5

- Standard-Fenstericon durch das IT-Solutions Logo ersetzt.
- `app_icon.ico` für PyInstaller ergänzt.
- GitHub Actions und lokaler Build verwenden jetzt das Logo als EXE-Icon.
- Tkinter-Fenster setzt das Logo auch in der Titelleiste.

# Änderungen Version 1.2.4

- Berichte werden nun im temporären Benutzerordner gespeichert.
- Der Dokumente-Ordner wird nicht mehr automatisch mit Netzwerkcheck-Berichten gefüllt.
- Der Bericht kann weiterhin direkt über den Button „HTML-Bericht öffnen“ geöffnet werden.
- Der Ausgabeordner kann weiterhin über den Button geöffnet werden.

# Änderungen Version 1.2.3

- Sichtbare CMD-Fenster bei Ping- und ARP-Abfragen unter Windows unterdrückt.
- Subprocess-Aufrufe verwenden unter Windows `CREATE_NO_WINDOW`.
- Der Scan sollte nun ohne aufploppende Konsolenfenster laufen.

# Änderungen Version 1.2.2

- Funktionslose Sidebar entfernt.
- Oberfläche kompakter und aufgeräumter gestaltet.
- Ergebnisliste zeigt vor dem ersten Scan keine Beispielwerte mehr.
- Während des Scans werden alte Werte geleert.
- KPI-Karten sind klickbar:
  - Gefundene Geräte springt zur Geräteliste.
  - Offene Dienste und kritische Risiken springen zur Risikoübersicht.
  - Bericht öffnet den letzten HTML-Bericht.
- Footer-Button für den Ausgabeordner ergänzt.
- Fenstergröße reduziert und Abstände verbessert.

# Änderungen Version 1.2.1

- Syntaxfehler in der modernen Oberfläche behoben.
- Mehrzeiliger Beschreibungstext im Scan-Card-Bereich korrekt escaped.
- GitHub Actions Build sollte jetzt wieder sauber durchlaufen.

# Änderungen Version 1.2.0

- Moderne Oberfläche im IT-Solutions Branding ergänzt.
- Logo in die Anwendung integriert.
- Sidebar-Navigation, Scan-Dashboard und Ergebnisübersicht ergänzt.
- KPI-Karten für Geräte, offene Dienste, kritische Risiken und Berichtstatus ergänzt.
- Ergebnisliste direkt in der Oberfläche sichtbar.
- Risikoübersicht direkt in der Oberfläche sichtbar.
- Buttons zum Öffnen des HTML-Berichts und Ausgabeordners ergänzt.

# Änderungen Version 1.1.0

- ARP-Auswertung ergänzt.
- Geräte, die per ARP sichtbar sind, werden zusätzlich im Bericht aufgeführt.
- MAC-Adressen werden angezeigt, sofern lokal verfügbar.
- Bericht spricht jetzt von „aktiv sichtbaren Geräten“ statt pauschal „Geräte gefunden“.
- Hinweis ergänzt, dass Router-Listen von Scan-Ergebnissen abweichen können.
- Hinweis ergänzt, dass Hostnamen aus DNS- oder Router-Caches stammen können.
- Unplausible Kombinationen wie IoT-Hostname mit riskanten Diensten werden markiert.
- Empfehlungen bei FTP und anderen Diensten vorsichtiger formuliert.
- HTML-Bericht um Erkennungsquelle, MAC-Adresse und Hinweise pro Gerät erweitert.
