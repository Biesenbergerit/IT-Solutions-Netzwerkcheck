# Änderungen Version 1.0.1

- Verhindert mehrfaches Öffnen der EXE durch versehentliches Mehrfachklicken.
- Netzwerkbereich wird sauber normalisiert.
  Beispiel: `192.168.0.139/24` wird intern und im Bericht zu `192.168.0.0/24`.
- Automatische Erkennung bleibt aktiv und nutzt die lokale IP des Standard-Netzwerkadapters.
- Bericht zeigt jetzt den echten CIDR-Netzbereich statt einer Host-IP mit `/24`.
