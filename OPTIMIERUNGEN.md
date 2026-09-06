# Umsetzung und Prüfung

Stand: 6. September 2026. Releasevorbereitung für 1.4.14 auf Basis von 1.4.13.
Signierung, Notarisierung und Veröffentlichung werden am erzeugten Paket geprüft.

| Punkt | Umsetzung | Nachweis |
| --- | --- | --- |
| Volltest/Oberflächentest | Ein Worker, vollständiger Bytevergleich, Restblock, strenge Lese-/Schreibfehlerprüfung; separate Phasenzeitmessung | Fehler an Byte 131 statt nur Byte 0, EOF- und Restblocktests |
| Sicheres Aushängen | Fehler führen zum Abbruch; physische Partitionen und zugehörige synthetische APFS-Volumes prüfen; erneute Prüfung nach Authentifizierung | Mount-Fixtures, lesender macOS-APFS-Zuordnungstest |
| Vollständiges Backup | Backend-Kapazität statt automatischer ISO-Kürzung; separater ISO-Extraktionsmodus; atomare Veröffentlichung einer vollständigen `.partial`-Datei; keine Überschreibung | Exakter Inhalt und Restbytes, EOF, bestehende Ziel-/Teildateien |
| Ablauf und Abbruch | Gemeinsame Auftragssperre einschließlich Updateinstallation; stabile IDs; privilegierter Supervisor mit Steuerkanal; Sperre erst nach Prozessende freigeben; blockierende Arbeiten aus dem Async-Executor verlagert | Sperrentest; stiller Prozess wird abgebrochen; falscher Exitstatus trotz `DONE` wird abgewiesen |
| Forensik-Erhebung | Ein nativer Scan pro Mountpunkt; begrenzte Toplisten; keine Symlink-Verfolgung/Mount-Überschreitung; sichtbare Fehler und Grenzen; native Dateisystemstatistik | Dateinamen mit Zeilenumbruch, Symlinks, System-/Nutzdatenzählung, nicht vorhandene Verzeichnisse |
| Image-Verifizierung | SHA-256 je Block während des Schreibens; Rücklesen ohne zweite XZ-Dekomprimierung; macOS-Dateicache für Geräte-I/O abgeschaltet; Fortschritt gedrosselt | Raw/XZ-Inhaltsvergleich, manipulierte Rücklesedaten, exakt ein XZ-Prozess |
| Aufbau und Darstellung | Eigene Module für Scan, Auftragssperre, Prozesssteuerung und I/O; gemeinsames Forensik-Modell/Renderer/CSS für Tab und Export; JSON-Schema 1.1 | Normaler UI-Ablauf mit simulierter IPC; 113 Elemente alle 12 px; Escaping- und Exporttests |
| Releaseprüfung | Rust-Entpackung wie im Updater; AppleDouble-/Pfad-/Bundleprüfung; danach Version, Codesignatur, Ticket und Gatekeeper; verpflichtendes Release-Gate | Archivtest; vorhandenes 1.4.13-Archiv erfolgreich entpackt und als Notarized Developer ID akzeptiert |
| Geschwindigkeitsmessung | Kurzprofil ca. 30 s pro Richtung; ausführliche 1/4/16-MiB-Messungen; gewichteter Durchsatz inklusive Schreib-Synchronisierung; MiB/s | Zeitbudget, Restblock, separate Messreihen, gewichteter Mittelwert und Flush-Zeit getestet |
| Surface/Stichprobe | Live-Durchsatz und ETA; einmalige Wiederholung; Eingrenzung auf 64-KiB-Bereiche; Weiterlauf bei EIO; höchstens 256 Fehlerbereiche im Detailbericht | Fehler mitten im Block, transiente Fehler, Geräteverlust, EOF, Listenbegrenzung und Stichprobenabdeckung getestet |

## Ausgeführte Prüfungen

- 28 Rust-Bibliothekstests erfolgreich; zwei macOS-Integrationstests im
  Standardlauf bewusst ausgenommen.
- Ein Rust-Archivtest erfolgreich.
- 27 Python-Tests erfolgreich.
- Dreizehn JavaScript-Tests erfolgreich (insgesamt 69 Standardtests).
- Zusätzlich der lesende macOS-Integrationstest zur APFS-Zuordnung erfolgreich.
- `cargo clippy ... -- -D warnings`, JavaScript-/Shell-Syntax und
  `git diff --check` erfolgreich.
- Browserprüfung mit echter Oberfläche und ausschließlich simulierter
  Tauri-Schnittstelle erfolgreich. Keine echte Passwortübertragung oder
  Datenträgeraktion durch diese Browserprüfung.
  Diagnose zusätzlich: Stichprobenwarnung, Datenanteil, Geschwindigkeitsprofile,
  destruktive Bestätigung, Einzelwert-Tabelle und Zurücksetzen alter Ergebnisse.
- Drei zusätzliche Regressionstests mit einer unprivilegierten sudo-Simulation:
  getrenntes Zurücksetzen/Validieren und anschließender Worker-Start;
  falsches Passwort mit geschlossenem Eingabekanal; Abbruch vor Authentifizierung.
- Bestehendes Updatearchiv 1.4.13: Rust-Entpackung, Version, Codesignatur,
  Notarisierungsticket und Gatekeeper erfolgreich. Dies ist ausdrücklich
  noch kein Release-Test eines Builds mit den neuen Änderungen.

## Noch offen: Hardware-Freigabe und Messung

Die drei vom Nutzer freigegebenen Medien wurden lesend identifiziert:
USB Disk 3.0 (62.264.442.880 Bytes), Spaceloop 4GB (4.146.069.504 Bytes),
MassStorageClass/SD (31.914.983.424 Bytes). Die zusätzlich angeschlossene
1-TB-Platte gehört **nicht** zum destruktiven Testumfang.

Die früheren Hardware-Teststarts scheiterten am macOS-Ordnerschutz bzw. warteten
auf die Administratorfreigabe. Beim erneuten, ausdrücklich freigegebenen
Diagnosetest wurden nur die beiden USB-Sticks ausgewählt; SD und 1-TB-Platte
waren nicht Teil des Testplans. Ein geerbtes geschütztes Arbeitsverzeichnis
wurde als erste Startursache behoben. Der App-Prozessstarter verwendet jetzt
ebenfalls ein neutrales Arbeitsverzeichnis und isolierte Python-Imports.

Der folgende Start scheiterte vor dem ersten Schreibzugriff an
`Operation not permitted: /dev/rdisk10`. Die macOS-Systemmeldungen belegen
`SystemPolicyRemovableVolumes` und `Python ... deny(1) file-read-data /dev/rdisk10`.
Die Administratorfreigabe allein reicht hier nicht; die Zugriffserlaubnis für
Wechselmedien muss durch den Nutzer erfolgen. Beide Testprozesse sind beendet.
Bis zu diesem Zeitpunkt wurde kein angeschlossener Datenträger durch diese
fehlgeschlagenen Teststarts beschrieben oder gelöscht.

Anschließend wurde die neue lokale App mit derselben Developer-ID und
Bundle-Kennung wie die installierte App gebaut und gestartet. Im echten
App-Ablauf wurde ein weiterer Startfehler sichtbar: `sudo -k -v` prüft das
Passwort, aktualisiert aber absichtlich keinen Credential-Cache. Der folgende
Aufruf `sudo -n` scheiterte deshalb mit `a password is required`, weiterhin vor
dem ersten Schreibzugriff. Korrigiert auf zwei getrennte Aufrufe (`sudo -k`,
danach `sudo -S -p "" -v`) und durch die drei oben genannten Tests abgesichert.
Der lokale Neubau trägt den Fenstertitel „Diagnosetest 2 – sudo-Fix“; er ist
signiert, aber nicht als Release notarisiert oder veröffentlicht.

## Erfolgreicher Hardware-Kurztest in der App

Am 6. September 2026 wurde der Kurztest im korrigierten, signierten App-Build
auf **Spaceloop 4GB (disk11, 4.146.069.504 Bytes)** vom Nutzer bestätigt und
erfolgreich abgeschlossen. Das echte App-Fenster zeigt:

- Start 15:38:50, Abschluss 15:39:54: ca. 64 Sekunden inklusive Vorbereitung.
- Blockgröße 8 MiB; 144 MiB geschrieben, 864 MiB gelesen.
- Schreibdurchsatz **4,8 MiB/s**, Lesedurchsatz **28,7 MiB/s**.
- 100 %, „Geschwindigkeitsmessung abgeschlossen“, Fehlerzähler 0.

Damit sind Passwortprüfung, nicht-interaktiver privilegierter Folgestart,
Gerätezugriff, beide Messphasen und Ergebnisdarstellung im echten App-Ablauf
bestätigt. Die Lesemenge enthält wiederholte Durchläufe durch den zuvor
geschriebenen Anfangsbereich: kein vollständiger Surface Scan und kein
Test der Dateiintegrität. Die ersten 144 MiB des Sticks wurden überschrieben,
einschließlich der vorderen Partitionstabelle; vor Wiederverwendung neu
partitionieren/formatieren. Der 62-GB-Stick, die SD-Karte und die 1-TB-Platte
wurden bei diesem erfolgreichen Test nicht beschrieben.

Noch offen: ausführliches Geschwindigkeitsprofil, vollständiger Surface Scan
und Stichproben-Scan auf echten Medien sowie der Kurztest des zweiten Sticks.

## Abschluss nach dem Brennen

Beim vom Nutzer ausgeführten Brennen von `desinfect2026.img.xz` auf disk10
wurde nach erfolgreichem Schreiben und Verifizieren um 16:19:46 ein Fehler
beim Wiedereinhängen gemeldet. Im DiskArbitration-Protokoll steht um
16:19:46.114 ein `disk eject`-Auftrag von `loginwindow`; der Auswurf war um
16:19:46.280 erfolgreich. Dessen Ursache ist weiterhin ungeklärt. Daraus
folgt insbesondere kein Nachweis eines beschädigten Btrfs-Dateisystems.

Die App meldet jetzt ein strukturiertes Ergebnis: bestätigtes Schreiben,
bestätigte Verifizierung (nur wenn angefordert) und eine separate optionale
Mount-/Auswurf-Warnung. Ein fehlgeschlagener Abschlussbefehl setzt bestätigte
Schreib-/Verifizierungsergebnisse nicht mehr auf Fehler zurück. I/O-Fehler,
Prüfsummenabweichungen, Abbruch und fehlende Worker-Bestätigungen bleiben
Fehler. Warnungen erscheinen separat im Fenster, Protokoll und in der
Benachrichtigung; der erfolgreiche Fortschritt bleibt bei 100 Prozent.

Verbindliche Auswurfregel: Ohne gesetzte Option wird ausschließlich
`mountDisk`, mit gesetzter Option ausschließlich `eject` aufgerufen. Kein
Fallback-Auswerfen bei Mountfehlern. Sieben Rust- und vier JavaScript-Tests
sichern die Abschlussfälle einschließlich beider Optionszustände ab.
Die unerwartete Auswurfanforderung des Betriebssystems ist damit ausdrücklich
noch nicht als behoben nachgewiesen. Der lokale Neubau für diese Änderung
trägt den Titel „Abschluss-Test 3“ und ist kein veröffentlichtes Release.

## Typografie der Diagnose-Auswertung (1.4.14)

Für den neuen Ergebnisbereich fehlte bisher eine Größenregel; Absätze und
Tabelle fielen auf die Browser-Vorgabe von 16 px zurück. Der Ergebnisbereich
und die Messprofil-Auswahl verwenden jetzt die kompakte 12-px-Systemschrift.
Absätze und Tabellenzellen sind normalgewichtig (400), Tabellenköpfe 600.
Ein Regressionstest prüft die CSS-Regeln. Im gerenderten UI wurden alle
12 geprüften Ergebnis-Elemente mit 12 px und derselben System-Schriftfamilie
gemessen; zusätzlich wurde die Darstellung visuell kontrolliert.

Vor einem späteren Hardwaretest müssen Gerätekennung, Modell und Kapazität
erneut geprüft werden. Das vorbereitete Testskript ist ausdrücklich destruktiv.
Eine reale Geschwindigkeitssteigerung auf USB/SD ist noch nicht gemessen;
die Tests belegen bisher Korrektheit, Darstellung und die entfallene zweite
XZ-Dekomprimierung. `tests/diagnostic_hardware_smoke.py` ist ausschließlich
opt-in und destruktiv; es prüft vor jeder Operation Gerätekennung, exakten
Mediennamen, Kapazität, extern/physisch/schreibbar sowie den Aushängezustand.
