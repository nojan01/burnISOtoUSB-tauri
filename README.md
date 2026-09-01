# 🔥 BurnISO to USB

<p align="center">
  <img src="src-tauri/icons/icon.png" width="128" height="128" alt="BurnISO to USB Icon">
</p>

<p align="center">
  <strong>Eine moderne macOS-App zum Brennen von ISO-Images auf USB-Sticks und zum Erstellen von USB-Backups</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#verwendung">Verwendung</a> •
  <a href="#tastenkürzel">Tastenkürzel</a> •
  <a href="#entwicklung">Entwicklung</a> •
  <a href="#lizenz">Lizenz</a>
</p>

---

## Features

### 🔥 ISO auf USB brennen
- **Schnelles Schreiben** von ISO-Images auf USB-Sticks
- **Byte-für-Byte Verifizierung** nach dem Brennen (optional)
- **Automatisches Auswerfen** des USB-Sticks nach Abschluss
- **Fortschrittsanzeige** in Echtzeit mit Phasenindikator

### 💿 USB-Backup erstellen
- **Sektorgenaues Backup (Raw)** - Komplettes 1:1 Image des gesamten USB-Sticks
- **Dateibasiertes Backup** - Nur belegte Daten, schneller und komprimiert (DMG)
- **Automatische Erkennung** des Dateisystems (APFS, HFS+, FAT32, ExFAT)
- **ISO-Image Erkennung** - Bei ISOs auf USB wird nur die tatsächliche Größe gesichert

### 🔍 USB prüfen (NEU!)
- **Surface Scan** - Liest alle Sektoren und findet Lesefehler (nicht-destruktiv, Daten bleiben erhalten)
- **Volltest** - Schreibt Testmuster (0x00, 0xFF) und verifiziert (destruktiv, löscht alle Daten!)
- **Geschwindigkeitstest** - Misst Lese- und Schreibgeschwindigkeit in MB/s
- **S.M.A.R.T. Status** - Zeigt Gesundheitsdaten für USB-Festplatten (mit [smartmontools](https://www.smartmontools.org/))
- **Echtzeit-Statistiken** - Geprüfte Sektoren, gefundene Fehler, Geschwindigkeit

> 💡 Für erweiterte S.M.A.R.T.-Daten: `brew install smartmontools`

### 🛠️ USB Tools
- **Formatieren** - FAT32, ExFAT, NTFS, ext2/3/4, APFS, HFS+ mit GPT oder MBR (Verschlüsselung für APFS/HFS+)
- **NTFS** - Erfordert [Paragon NTFS](https://www.paragon-software.com/de/home/ntfs-mac/)
- **ext2/3/4** - Erfordert [Paragon extFS](https://www.paragon-software.com/de/home/extfs-mac/)
- **First Aid** - Repariert Dateisystem-Fehler auf USB-Sticks
- **Sicher Löschen** - 4 Sicherheitsstufen (Schnell bis Gutmann 35×)
- **Boot-Analyse** - Prüft Bootfähigkeit (MBR, GPT, EFI, El Torito)

### 🔍 Forensik-Analyse (NEU in 1.3.0)
- **Geräteinformationen** - Hersteller, Modell, Seriennummer
- **Partitionen** - Layout, Dateisysteme, Größen
- **Boot-Strukturen** - MBR, GPT, EFI-Partition
- **Hash-Werte** - MD5, SHA-256 der ersten Sektoren
- **Paragon-Treiber** - Zeigt an ob NTFS und extFS Treiber verfügbar sind
- **Export** - JSON (Zwischenablage) oder HTML-Report

### 🌍 Mehrsprachig
- **Deutsch** und **English** - Umschaltbar über das Hilfe-Menü
- Automatische Erkennung der Systemsprache beim ersten Start

### 🎨 Design
- **Dunkles Design** (Standard) - Schont die Augen
- **Helles Design** - Für helle Umgebungen
- Umschaltbar über das Fenster-Menü

### ⌨️ Native macOS-Integration
- Vollständiges macOS-Menü mit allen Funktionen
- Tastenkürzel für schnellen Zugriff
- Fensterposition wird gespeichert

---

## Installation

### Voraussetzungen
- macOS 10.15 (Catalina) oder neuer
- Administrator-Rechte (für USB-Zugriff)
- Python 3 zum Brennen und sicheren Löschen (bei Bedarf: `brew install python`)
- Für XZ-komprimierte Images: `xz` (bei Bedarf: `brew install xz`)

### Download
1. Lade die neueste Version von der [Releases-Seite](https://github.com/nojan01/burniso-tauri/releases) herunter
2. Entpacke die ZIP-Datei
3. Ziehe **BurnISO to USB.app** in den Programme-Ordner
4. Beim ersten Start: Rechtsklick → Öffnen (wegen Gatekeeper)

### Aus Quellcode bauen
```bash
# Repository klonen
git clone https://github.com/nojan01/burniso-tauri.git
cd burniso-tauri

# Abhängigkeiten installieren (Rust und Node.js erforderlich)
cargo tauri build

# App befindet sich in: src-tauri/target/release/bundle/macos/
```

---

## Verwendung

### ISO auf USB brennen

1. **ISO-Datei auswählen**
   - Klicke auf "Durchsuchen" oder verwende `⌘O`
   - Wähle die gewünschte ISO-Datei aus

2. **USB-Stick auswählen**
   - Stecke den USB-Stick ein
   - Wähle ihn aus dem Dropdown-Menü
   - Bei Bedarf: `⌘R` zum Aktualisieren der Liste

3. **Optionen festlegen**
   - ✅ **Verifizieren** - Empfohlen! Prüft ob alle Daten korrekt geschrieben wurden
   - ✅ **Auswerfen** - Wirft den Stick nach Abschluss sicher aus

4. **Brennvorgang starten**
   - Klicke auf "🔥 ISO auf USB brennen" oder `⌘B`
   - Gib dein macOS-Passwort ein (für Schreibzugriff)
   - Warte bis der Vorgang abgeschlossen ist

> ⚠️ **Warnung**: Alle Daten auf dem USB-Stick werden unwiderruflich gelöscht!

### USB-Backup erstellen

1. **USB-Stick auswählen**
   - Stecke den USB-Stick ein
   - Wähle ihn aus dem Dropdown-Menü

2. **Speicherort wählen**
   - Klicke auf "Speichern unter" oder verwende `⌘S`
   - Wähle den Zielordner und Dateinamen

3. **Sicherungsmodus wählen**
   - **Sektorgenau (Raw)**: Exaktes 1:1 Abbild des gesamten Sticks (.iso)
   - **Dateibasiert**: Nur belegte Daten, komprimiert (.dmg)
   
   > 💡 Dateibasiert ist nur bei unterstützten Dateisystemen verfügbar

4. **Backup starten**
   - Klicke auf "💿 USB sichern" oder `⌘⇧B`
   - Bei Raw-Backup: macOS-Passwort eingeben

### USB prüfen (Diagnose)

1. **USB-Stick auswählen**
   - Stecke den USB-Stick ein
   - Wähle ihn aus dem Dropdown-Menü
   - S.M.A.R.T. Status wird automatisch angezeigt (falls verfügbar)

2. **Testmodus wählen**
   - **🔍 Surface Scan**: Liest alle Sektoren ohne Daten zu löschen
   - **⚠️ Volltest**: Schreibt Testmuster und verifiziert (LÖSCHT ALLE DATEN!)
   - **⚡ Geschwindigkeitstest**: Misst Lese-/Schreibgeschwindigkeit (LÖSCHT ALLE DATEN!)

3. **Test starten**
   - Klicke auf "🔍 Test starten" oder `⌘D`
   - Gib dein macOS-Passwort ein
   - Fortschritt und Statistiken werden in Echtzeit angezeigt

> 💡 **Tipp**: Für erweiterte S.M.A.R.T.-Daten bei USB-Festplatten: `brew install smartmontools`

---

## Tastenkürzel

| Funktion | Tastenkürzel |
|----------|--------------|
| ISO-Datei öffnen | `⌘O` |
| Speicherort wählen | `⌘S` |
| USB-Geräte aktualisieren | `⌘R` |
| Tab: ISO → USB | `⌘1` |
| Tab: USB → ISO | `⌘2` |
| Tab: USB prüfen | `⌘3` |
| Tab: USB Tools | `⌘4` |
| Tab: Forensik | `⌘5` |
| ISO auf USB brennen | `⌘B` |
| USB sichern | `⌘⇧B` |
| USB-Diagnose starten | `⌘D` |
| Vorgang abbrechen | `⌘.` |
| Dunkles Design | `⌘⇧D` |
| Helles Design | `⌘⇧L` |
| Fenster schließen | `⌘W` |
| App beenden | `⌘Q` |

---

## Unterstützte Formate

### ISO-Dateien (Brennen)
- Standard ISO 9660 Images
- Linux-Distributionen (Ubuntu, Fedora, Debian, etc.)
- Windows ISO-Images
- macOS Installer Images
- Hybrid ISO/IMG Images
- XZ-komprimierte ISO/IMG Images (automatisch beim Schreiben entpackt)

### Dateisysteme (Backup)
- **APFS** - Apple File System
- **HFS+** - Mac OS Extended
- **FAT32** - Windows-kompatibel
- **ExFAT** - Große Dateien, plattformübergreifend
- **ISO 9660** - CD/DVD Images (automatische Größenerkennung)

---

## Fehlerbehebung

### "Keine USB-Sticks gefunden"
- Stelle sicher, dass der USB-Stick korrekt eingesteckt ist
- Nur **externe physische Geräte** werden angezeigt (keine Disk-Images)
- Klicke auf 🔄 zum Aktualisieren

### "Passwort wird nicht akzeptiert"
- Verwende dein **macOS-Benutzerpasswort** (nicht Apple-ID)
- Der Benutzer muss Administrator-Rechte haben

### "Verifizierung fehlgeschlagen"
- Der USB-Stick könnte defekt sein
- Versuche einen anderen USB-Port
- Verwende einen anderen USB-Stick

### App startet nicht
- Rechtsklick auf die App → "Öffnen" (bei Gatekeeper-Warnung)
- macOS 10.15 oder neuer erforderlich

---

## Entwicklung

### Technologie-Stack
- **[Tauri v2](https://tauri.app/)** - Rust-basiertes App-Framework
- **Rust** - Backend-Logik und System-APIs
- **HTML/CSS/JavaScript** - Frontend
- **diskutil** - macOS Disk-Management

### Projekt-Struktur
```
burniso-tauri/
├── src/                    # Frontend (HTML, CSS, JS)
│   ├── index.html
│   ├── styles.css
│   ├── main.js
│   ├── i18n.js            # Internationalisierung
│   └── i18n/              # Übersetzungen
│       ├── de.json
│       └── en.json
├── src-tauri/             # Backend (Rust)
│   ├── src/
│   │   ├── main.rs
│   │   └── lib.rs         # Hauptlogik
│   ├── icons/             # App-Icons
│   ├── Cargo.toml
│   └── tauri.conf.json
└── README.md
```

### Entwicklungsumgebung einrichten
```bash
# Rust installieren
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Tauri CLI installieren
cargo install tauri-cli

# Im Entwicklungsmodus starten
cargo tauri dev

# Release-Build erstellen
cargo tauri build
```

---

## Lizenz

**MIT License** — Copyright (c) 2026 Norbert Jander. Siehe [LICENSE](LICENSE) für den vollständigen Text.

Die Software wird „wie besehen“ und **ohne jede Gewährleistung** bereitgestellt.
Da dieses Werkzeug Datenträger direkt beschreibt und sicher löscht, kann eine
Fehlbedienung zu **unwiederbringlichem Datenverlust** führen. Die Nutzung erfolgt
auf eigene Verantwortung.

### Komponenten Dritter

Eine vollständige Aufstellung aller verwendeten Fremdkomponenten und ihrer
Lizenzen findet sich in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Kurzfassung: Alle Abhängigkeiten stehen unter permissiven Lizenzen (überwiegend
MIT bzw. Apache-2.0). Fünf Pakete aus dem WebView-Unterbau stehen unter der
MPL-2.0 und werden unverändert eingebunden. Externe Systemwerkzeuge wie
`smartctl` (GPL) werden **nicht mitgeliefert**, sondern nur aufgerufen, sofern
sie auf dem System vorhanden sind.

---

## Autor

**Norbert Jander** - [GitHub](https://github.com/nojan01)

---

<p align="center">
  Made with ❤️ and 🦀 Rust
</p>
