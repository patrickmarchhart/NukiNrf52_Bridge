# Nuki-BLE-Steuerung: UART-Protokoll für Loxone

Dieses Board steuert ein Nuki Smart Lock per Bluetooth LE und stellt dafür eine
zweite, dedizierte UART (`uart1`) bereit, über die ein eigenes Loxone-Modul das
Schloss ansteuern und Statuswerte abfragen kann. Diese UART ist bewusst von der
menschenlesbaren Shell auf `uart0` (Konsole/Debug-Ausgabe, siehe `nuki_shell.c`)
getrennt: `uart1` spricht ausschließlich das unten beschriebene, maschinell
parsbare Zeilenprotokoll — keine Log-Zeilen, keine Prompts.

Implementiert in [`src/nuki_uart_proto.c`](src/nuki_uart_proto.c) /
[`nuki_uart_proto.h`](src/nuki_uart_proto.h).

## 1. Hardware / Verkabelung

| Signal | Pin (nRF52840) | Richtung             |
|--------|-----------------|----------------------|
| TX     | P0.20           | Board → Loxone (RX)  |
| RX     | P0.22           | Loxone (TX) → Board  |
| GND    | –               | gemeinsame Masse     |

Pinbelegung siehe [`boards/nrf52840dk_nrf52840.overlay`](boards/nrf52840dk_nrf52840.overlay).

**UART-Parameter:** 115200 Baud, 8 Datenbits, kein Paritätsbit, 1 Stoppbit,
keine Flusskontrolle (8N1). Die Baudrate ist über `current-speed` im Overlay
anpassbar, falls das Loxone-Modul eine andere Rate benötigt.

Pegel: 3,3 V LVTTL (nRF52840-GPIO) — bei einem Loxone-Modul mit 5V-UART ist ein
Pegelwandler/Spannungsteiler erforderlich.

## 2. Protokollformat

- Ein Kommando pro Zeile, abgeschlossen mit `\n` (LF). `\r` (CR) wird toleriert
  und ignoriert (CRLF- und LF-only-Absender funktionieren beide).
- Kommandos sind **nicht case-sensitiv** (`lock`, `LOCK`, `Lock` sind gleichwertig).
- Zeilen über 63 Zeichen werden abgeschnitten; die Antwort auf ein Kommando
  kommt immer als **eine** Zeile zurück, ebenfalls `\n`-terminiert.
- Es gibt kein asynchrones Push von Statusänderungen — Loxone fragt aktiv ab
  (Polling), passend zum "Connect-on-Demand"-Modell der Firmware (siehe unten).

### Antwortformate

| Ergebnis | Format                              | Beispiel |
|----------|--------------------------------------|----------|
| Erfolg   | `OK` oder `OK <SCHLÜSSEL=WERT ...>`  | `OK LOCKED` |
| Fehler   | `ERR <errno> <STABILER_CODE>`        | `ERR -2 NOT_PAIRED` |

Für Fehlerauswertung in Loxone immer den **zweiten Token** (`STABILER_CODE`)
verwenden, nicht die Zahl — die Zahl ist der rohe errno-Wert der Firmware und
dient nur der Diagnose/dem Log.

## 3. Kommandos

### `STATUS`
Liefert Pairing-/Verbindungsstatus, ohne Bluetooth zu benutzen (rein aus dem
gespeicherten Zustand).

```
> STATUS
< OK PAIRED=1 CONNECTED=0 READY=0
```

| Feld        | Bedeutung |
|-------------|-----------|
| `PAIRED`    | 1 = Schloss ist gepairt (Zugangsdaten im Flash gespeichert) |
| `CONNECTED` | 1 = gerade eine BLE-Verbindung zum Schloss aktiv (i.d.R. nur kurz während einer Operation) |
| `READY`     | 1 = aktive Verbindung UND Keyturner-Service bereits entdeckt |

### `PAIR`
Führt das Pairing mit dem Schloss durch. Das Schloss muss vorher in den
Pairing-Modus versetzt werden (Taste ca. 5 s gedrückt halten, LED blinkt).
Blockiert bis Erfolg, Fehlschlag oder Timeout (mehrere Sekunden).

```
> PAIR
< OK PAIRED
```

Bei Fehlschlag z. B. `ERR -116 TIMEOUT` (Schloss nicht im Pairing-Modus /
außer Reichweite).

### `STATE`
Liefert den zuletzt bekannten Schlosszustand.

```
> STATE
< OK LOCK_STATE=3 LOCK_STATE_NAME=unlocked BATTERY=87 CRITICAL=0 DOOR_STATE=3 DOOR_STATE_NAME=closed YEAR=2026 MONTH=7 DAY=26 HOUR=14 MIN=2 SEC=10 TZ=0 AGE_S=12
```

| Feld               | Bedeutung |
|--------------------|-----------|
| `LOCK_STATE`        | numerischer Nuki-Lock-State |
| `LOCK_STATE_NAME`    | Klartext (`locked`, `unlocked`, `unlatched`, `motor blocked`, …) |
| `BATTERY`            | Batterieladung in % |
| `CRITICAL`           | 1 = Batterie kritisch niedrig |
| `DOOR_STATE` / `DOOR_STATE_NAME` | Türsensor-Zustand (numerisch/Klartext), `255`/`unavailable` wenn kein Türsensor verbaut |
| `YEAR..TZ`           | Zeitstempel + Zeitzonen-Offset (Minuten), wie vom Schloss zuletzt gemeldet |
| `AGE_S`              | Alter dieses Werts in Sekunden (siehe unten) |

**Wichtig — `STATE` ist ein reiner Cache-Zugriff:** Die Firmware fragt den
Schlosszustand **im Hintergrund alle 15 Minuten** automatisch per BLE ab und
speichert das Ergebnis zwischen (siehe `nuki_app.c`, `state_poll_handler`).
`STATE` über UART liest nur diesen Cache und antwortet dadurch **sofort**
(keine mehrsekündige BLE-Verbindung pro Abfrage). `AGE_S` zeigt an, wie alt
der zurückgegebene Wert ist — Loxone kann damit selbst entscheiden, ob ein
Wert noch aktuell genug ist.

Direkt nach dem Boot, bevor der erste Hintergrund-Poll abgeschlossen ist, gibt
es noch keinen Cache-Wert:

```
> STATE
< ERR -61 NO_DATA_YET
```

Ein einfaches Nachfragen ein paar Sekunden später reicht dann aus.

### `LOCK` / `UNLOCK` / `UNLATCH`
Führt die jeweilige Schließaktion aus. Baut dafür kurzzeitig eine eigene
BLE-Verbindung auf (unabhängig vom Status-Cache) und dauert typischerweise
1-3 Sekunden.

```
> LOCK
< OK LOCKED

> UNLOCK
< OK UNLOCKED

> UNLATCH
< OK UNLATCHED
```

### `CALIBRATE <pin>`
Startet die Kalibrierung (voller Motorlauf zum Erlernen der mechanischen
Endanschläge — dieselbe Aktion wie beim Ersteinrichten in der Nuki-App).
Erfordert die Security-PIN des Schlosses als Parameter.

```
> CALIBRATE 1234
< OK CALIBRATED
```

## 4. Fehlercodes

| `errno` | Code             | Bedeutung |
|---------|------------------|-----------|
| `-2`    | `NOT_PAIRED`     | Kein Pairing vorhanden — erst `PAIR` ausführen |
| `-5`    | `ERROR`          | Sonstiger interner/BLE-Fehler (siehe Firmware-Log auf uart0) |
| `-11`   | `TIMEOUT`        | Vorgang abgebrochen/timed out |
| `-22`   | `INVALID_ARGS`   | Ungültiges Argument (z. B. PIN nicht numerisch oder > 65535 bei `CALIBRATE`) |
| `-61`   | `NO_DATA_YET`    | Nur bei `STATE`: noch kein Hintergrund-Poll abgeschlossen |
| `-77`   | `BADMSG`         | Unerwartete/fehlerhafte Antwort vom Schloss (BLE-Protokollebene) |
| `-116`  | `TIMEOUT`        | Verbindungsaufbau/Scan zum Schloss abgelaufen |
| `-128`  | `NOT_CONNECTED`  | Verbindung zum Schloss verloren/nicht zustande gekommen |
| `-134`  | `UNSUPPORTED`    | Erwarteter GATT-Service/Charakteristik nicht gefunden (z. B. Pairing-Service beim `PAIR` fehlt) |
| —       | `UNKNOWN_COMMAND`| Unbekanntes Kommando (Antwort: `ERR -22 UNKNOWN_COMMAND`) |

## 5. Hinweise zur Integration

- **Ein Vorgang nach dem anderen:** Alle Kommandos außer `STATUS` und `STATE`
  (die aus Cache/gespeichertem Zustand beantwortet werden) blockieren die
  UART-Antwort, bis der jeweilige BLE-Vorgang abgeschlossen ist. Das
  Loxone-Modul sollte auf die Antwortzeile warten, bevor es das nächste
  Kommando sendet.
- **Nur eine BLE-Verbindung gleichzeitig:** Die meisten Nuki-Schlösser
  akzeptieren nur eine aktive BLE-Verbindung. Die Firmware verbindet sich
  daher nur für die Dauer einer einzelnen Operation (Pairing/Status-Poll/
  Lock-Aktion) und trennt danach sofort wieder — die offizielle Nuki-App
  bleibt so weiterhin nutzbar. Ein internes Lock serialisiert dabei Shell
  (uart0), dieses Loxone-Protokoll (uart1) und den Hintergrund-Poller
  gegeneinander, sodass sie sich nicht gegenseitig stören.
- **Erstinbetriebnahme:** Vor der ersten Nutzung muss einmalig `PAIR`
  ausgeführt werden (Schloss zuvor in Pairing-Modus versetzen). Die
  Pairing-Daten werden dauerhaft im Flash gespeichert und überstehen einen
  Neustart des Boards.
