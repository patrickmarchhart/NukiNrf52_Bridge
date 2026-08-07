# Nuki-BLE-Steuerung: UART-Protokoll für Loxone

Dieses Board steuert ein Nuki Smart Lock per Bluetooth LE und stellt dafür eine
zweite, dedizierte UART (`uart1`) bereit, über die ein eigenes Loxone-Modul das
Schloss ansteuern und Statuswerte abfragen kann. Diese UART ist bewusst von der
menschenlesbaren Shell auf `uart0` (Konsole/Debug-Ausgabe, siehe `nuki_shell.c`)
getrennt: `uart1` spricht ein **binäres Frame-Protokoll** — jede Anfrage und
jede Antwort ist ein fest definiertes Byte-Layout (Struct), kein Text.

Implementiert in [`src/nuki_uart_proto.c`](src/nuki_uart_proto.c) /
[`nuki_uart_proto.h`](src/nuki_uart_proto.h) (dort auch die kanonischen
C-Struct-Definitionen).

## 1. Hardware / Verkabelung

| Signal | Pin (nRF52840) | Richtung             |
|--------|-----------------|----------------------|
| TX     | P0.20           | Board → Loxone (RX)  |
| RX     | P0.22           | Loxone (TX) → Board  |
| GND    | –               | gemeinsame Masse     |

Pinbelegung siehe [`boards/nrf52840dk_nrf52840.overlay`](boards/nrf52840dk_nrf52840.overlay).

**UART-Parameter:** 115200 Baud, 8 Datenbits, kein Paritätsbit, 1 Stoppbit,
keine Flusskontrolle (8N1). Die Baudrate ist über `current-speed` im Overlay
anpassbar. Pegel: 3,3 V LVTTL — bei einem Loxone-Modul mit 5V-UART ist ein
Pegelwandler/Spannungsteiler nötig.

## 2. Frame-Format (Byte-Layout)

Beide Richtungen (Request Loxone→Board, Response Board→Loxone) verwenden
denselben Rahmenaufbau, aber ein unterschiedliches Startbyte, sodass allein
am ersten Byte erkennbar ist, ob ein Frame ein Request oder eine Response
ist (praktisch z. B. beim Mitschneiden mit einem Logic Analyzer):

| Offset      | Größe   | Feld      | Bedeutung |
|-------------|---------|-----------|-----------|
| 0           | 1       | `SOF`     | `0xA5` bei einem Request (Loxone→Board), `0x5A` bei einer Response (Board→Loxone) |
| 1           | 1       | `CMD`     | Befehlscode (siehe Abschnitt 3) |
| 2           | 1       | `LEN`     | Anzahl der folgenden Payload-Bytes (0–32) |
| 3           | `LEN`   | `PAYLOAD` | Rohbytes des Request-/Response-Structs zu `CMD` |

Gesamtlänge eines Frames = `3 + LEN` Bytes. Es gibt bewusst **keine
CRC/Prüfsumme** — uart1 ist eine kurze, direkte Punkt-zu-Punkt-Verbindung
zwischen zwei Boards (kein geteiltes/funkbasiertes Medium), daher wurde auf
eine Integritätsprüfung verzichtet, um beide Seiten (insbesondere die
Loxone-Implementierung) einfach zu halten.

- **Mehrbyte-Felder** innerhalb des Payloads (z. B. `uint16_t`, `int32_t`)
  sind **Little-Endian**, da sie 1:1 dem Speicherlayout der nRF52840-Structs
  entsprechen (kein manuelles Serialisieren in der Firmware nötig).
- **Request-Frames** (Loxone → Board): `CMD` wählt die Operation, `PAYLOAD`
  ist das passende `nuki_uart_req_*`-Struct (die meisten Befehle brauchen
  keins, `LEN=0`).
- **Response-Frames** (Board → Loxone): `CMD` ist eine Kopie des Befehls, auf
  den geantwortet wird (so lässt sich die Antwort ohne zusätzlichen Zustand
  dem richtigen Struct-Typ zuordnen). `PAYLOAD` beginnt **immer** mit einem
  `int32_t rc` (0 = Erfolg, sonst negativer Fehlercode/errno) — bei `rc != 0`
  sind alle weiteren Felder auf 0 gesetzt und ohne Bedeutung.

Es gibt kein asynchrones Push von Statusänderungen — Loxone fragt aktiv ab
(Polling), passend zum "Connect-on-Demand"-Modell der Firmware (siehe unten).

## 3. Befehle und Structs

### Übersicht

| `CMD` | Name        | Beschreibung | Request-Payload | Response-Payload |
|-------|-------------|---------------|------------------|-------------------|
| `1`   | `STATUS`    | Pairing-/Verbindungsstatus, ohne BLE-Zugriff | keins | `nuki_uart_resp_status` (7 B) |
| `2`   | `PAIR`      | Pairing mit dem Schloss durchführen | keins | `nuki_uart_resp_simple` (4 B) |
| `3`   | `STATE`     | Zwischengespeicherten Schlosszustand lesen (sofortige Antwort) | keins | `nuki_uart_resp_state` (21 B) |
| `4`   | `LOCK`      | Tür verschließen | keins | `nuki_uart_resp_simple` (4 B) |
| `5`   | `UNLOCK`    | Tür entriegeln | keins | `nuki_uart_resp_simple` (4 B) |
| `6`   | `UNLATCH`   | Tür entriegeln und öffnen (Falle) | keins | `nuki_uart_resp_simple` (4 B) |
| `7`   | `CALIBRATE` | Kalibrierung (voller Motorlauf) starten | `nuki_uart_req_calibrate` (2 B) | `nuki_uart_resp_simple` (4 B) |

Details zu jedem Befehl (inkl. Byte-Layout der Structs) folgen unten.

### `1` — STATUS
Liefert Pairing-/Verbindungsstatus, ohne Bluetooth zu benutzen.

Request: kein Payload (`LEN=0`).

Response — `struct nuki_uart_resp_status` (7 Byte):

| Offset | Typ       | Feld        | Bedeutung |
|--------|-----------|-------------|-----------|
| 0      | `int32_t` | `rc`        | 0 = Erfolg |
| 4      | `uint8_t` | `paired`    | 1 = Zugangsdaten vorhanden |
| 5      | `uint8_t` | `connected` | 1 = gerade eine aktive BLE-Verbindung |
| 6      | `uint8_t` | `ready`     | 1 = Verbindung aktiv und Keyturner-Service entdeckt |

Beispiel — Request:
```
A5 01 00
```
Antwort (`rc=0`, `paired=1`, `connected=0`, `ready=0`):
```
5A 01 07 00 00 00 00 01 00 00
```

### `2` — PAIR
Führt das Pairing durch (Schloss vorher in Pairing-Modus versetzen, Taste
~5 s halten). Blockiert bis Erfolg/Fehler/Timeout (mehrere Sekunden).

Request: kein Payload. Response: `struct nuki_uart_resp_simple` (4 Byte, nur
`rc`).

Beispiel — Request:
```
A5 02 00
```
Antwort (`rc=0`):
```
5A 02 04 00 00 00 00
```

### `3` — STATE
Liefert den zuletzt bekannten Schlosszustand — **aus dem Cache**, den der
Hintergrund-Poller alle 15 Minuten aktualisiert (siehe `nuki_app.c`,
`state_poll_handler`; 15 min entspricht dem Standard-Poll-Intervall der
offiziellen Nuki Bridge). Antwortet dadurch sofort, ohne live per BLE zu
lesen.

Request: kein Payload.

Response — `struct nuki_uart_resp_state` (21 Byte):

| Offset | Typ       | Feld                  | Bedeutung |
|--------|-----------|-----------------------|-----------|
| 0      | `int32_t` | `rc`                  | 0 = Erfolg, `-61` = noch kein Poll abgeschlossen (kurz nach Boot) |
| 4      | `uint8_t` | `lock_state`          | numerischer Nuki-Lock-State (siehe unten) |
| 5      | `uint8_t` | `battery_percent`     | Batterieladung in % |
| 6      | `uint8_t` | `critical_battery`    | 1 = Batterie kritisch niedrig |
| 7      | `uint8_t` | `door_sensor_state`   | Türsensor-Zustand (siehe unten), `0` = kein Sensor |
| 8      | `uint16_t`| `year`                | Zeitstempel (vom Schloss zuletzt gemeldet) |
| 10     | `uint8_t` | `month`               | |
| 11     | `uint8_t` | `day`                 | |
| 12     | `uint8_t` | `hour`                | |
| 13     | `uint8_t` | `minute`              | |
| 14     | `uint8_t` | `second`              | |
| 15     | `int16_t` | `timezone_offset_min` | Zeitzonen-Offset in Minuten |
| 17     | `int32_t` | `age_sec`             | Alter des Cache-Werts in Sekunden |

**`lock_state`-Werte:** `0` uncalibrated, `1` locked, `2` unlocking, `3`
unlocked, `4` locking, `5` unlatched, `6` unlocked (lock’n’go active), `7`
unlatching, `252` calibration, `253` boot run, `254` motor blocked, jeder
andere Wert = undefined.

**`door_sensor_state`-Werte:** `0` unavailable (kein Türsensor), `1`
deactivated, `2` door closed, `3` door opened, `4` door state unknown, `5`
calibrating, `16` uncalibrated, `240` tampered, jeder andere Wert = unknown.

Beispiel — Request:
```
A5 03 00
```
Antwort (`rc=0`, `lock_state=3` unlocked, `battery=87%`, `year=2026`,
`age_sec=42`, ...):
```
5A 03 15 00 00 00 00 03 57 00 03 EA 07 08 07 0E 02 0A 00 00 2A 00 00 00
```
(`15` = `LEN`=21 dezimal, `EA 07` = Jahr 2026 Little-Endian, `2A 00 00 00` =
`age_sec`=42)

### `4` — LOCK / `5` — UNLOCK / `6` — UNLATCH
Führt die jeweilige Schließaktion aus (eigene kurzzeitige BLE-Verbindung,
1-3 Sekunden). Request: kein Payload. Response: `struct nuki_uart_resp_simple`
(nur `rc`).

Beispiel `LOCK` (`CMD=4`) — Request:
```
A5 04 00
```
Antwort bei Erfolg (`rc=0`):
```
5A 04 04 00 00 00 00
```
Antwort bei Fehler, z. B. nicht gepairt (`rc=-2`) — Fehlerantworten sehen bei
allen Befehlen gleich aus, nur `CMD` und `rc` ändern sich:
```
5A 04 04 FE FF FF FF
```

Beispiel `UNLOCK` (`CMD=5`) — Request:
```
A5 05 00
```
Antwort (`rc=0`):
```
5A 05 04 00 00 00 00
```

Beispiel `UNLATCH` (`CMD=6`) — Request:
```
A5 06 00
```
Antwort (`rc=0`):
```
5A 06 04 00 00 00 00
```

### `7` — CALIBRATE
Startet die Kalibrierung (voller Motorlauf). Erfordert die Security-PIN.

Request — `struct nuki_uart_req_calibrate` (2 Byte):

| Offset | Typ        | Feld  |
|--------|------------|-------|
| 0      | `uint16_t` | `pin` |

Response: `struct nuki_uart_resp_simple` (nur `rc`).

Beispiel — Request mit PIN 1234 (`pin` als `uint16_t` Little-Endian,
`1234 = 0x04D2`):
```
A5 07 02 D2 04
```
Antwort (`rc=0`):
```
5A 07 04 00 00 00 00
```

## 4. Fehlercodes (`rc`)

| `rc`    | Bedeutung |
|---------|-----------|
| `-2`    | Kein Pairing vorhanden — erst `2` (PAIR) ausführen |
| `-5`    | Sonstiger interner/BLE-Fehler (siehe Firmware-Log auf uart0) |
| `-11`   | Vorgang abgebrochen/timed out |
| `-22`   | Ungültiger Befehl/Parameter (z. B. unbekannter `CMD`, falsche `LEN` bei `CALIBRATE`) |
| `-61`   | Nur bei `3` (STATE): noch kein Hintergrund-Poll abgeschlossen |
| `-77`   | Unerwartete/fehlerhafte Antwort vom Schloss (BLE-Protokollebene) |
| `-116`  | Verbindungsaufbau/Scan zum Schloss abgelaufen |
| `-128`  | Verbindung zum Schloss verloren/nicht zustande gekommen |
| `-134`  | Erwarteter GATT-Service/Charakteristik nicht gefunden (z. B. Pairing-Service beim `PAIR` fehlt) |

## 5. Hinweise zur Integration

- **Ein Vorgang nach dem anderen:** Alle Befehle außer `1` (STATUS) und `3`
  (STATE) blockieren die Antwort, bis der jeweilige BLE-Vorgang abgeschlossen
  ist. Das Loxone-Modul sollte auf die Antwort warten, bevor es den nächsten
  Request sendet.
- **Nur eine BLE-Verbindung gleichzeitig:** Die meisten Nuki-Schlösser
  akzeptieren nur eine aktive BLE-Verbindung. Die Firmware verbindet sich
  daher nur für die Dauer einer einzelnen Operation und trennt danach sofort
  wieder — die offizielle Nuki-App bleibt so weiterhin nutzbar. Ein internes
  Lock serialisiert dabei Shell (uart0), dieses Loxone-Protokoll (uart1) und
  den Hintergrund-Poller gegeneinander.
- **Erstinbetriebnahme:** Vor der ersten Nutzung muss einmalig `2` (PAIR)
  ausgeführt werden (Schloss zuvor in Pairing-Modus versetzen). Die
  Pairing-Daten werden dauerhaft im Flash gespeichert und überstehen einen
  Neustart des Boards.
- **Keine Integritätsprüfung:** Da es keine CRC gibt, wird ein durch einen
  Übertragungsfehler verändertes Byte nicht erkannt - `LEN` und `PAYLOAD`
  werden als gültig angenommen, sobald genug Bytes eingetroffen sind. Für die
  kurze, direkte Verkabelung zwischen Board und Loxone-Modul wird das als
  ausreichend robust eingeschätzt; nur eine kaputte `LEN` (zu groß) oder ein
  fehlendes `SOF` führt zum Resync auf das nächste `SOF`-Byte.
