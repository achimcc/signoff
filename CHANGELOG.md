# Changelog

## 0.3.0 — 2026-10-01

Befund B143 aus dem IT-Sicherheits-Audit 3 des Homeservers (`low`): Die
Werkskonto-Probe kannte für einen Dienst ohne Probe nur `undeclared`,
konnte eine abgewiesene Anmeldung nicht von einer angenommenen
unterscheiden, wo beide mit HTTP 200 antworten, und ein `undeclared` machte
nie einen Lauf rot. Drei Erweiterungen, die Vorgabe bleibt in allen drei
unverändert.

- **Begründete Ausnahme: `no_factory_login = "<reason>"`** je Dienst. Der
  Dienst hat ab Werk kein Konto (oder die lokale Anmeldung ist
  abgeschaltet), und jemand hat den Grund hingeschrieben. Urteil
  `n/a` mit dem Grund als Detail, nichts wird probiert, der Exit-Code
  ändert sich nicht. Zusammen mit `[service.factory_login]` am selben
  Dienst ist es ein Konfigurationsfehler, ein leerer oder nur aus
  Leerzeichen bestehender Grund ebenso.
- **Ablehnung am Antworttext: `factory_login.reject_body = "<substring>"`.**
  qBittorrent beantwortet eine falsche Anmeldung mit HTTP 200 und `Fails.`,
  eine richtige mit HTTP 200 und `Ok.`. Ist das Feld gesetzt, gilt eine
  Antwort nur als abgewiesen, wenn ihr Status in `reject` steht UND der
  Körper den Teilstring enthält; Status in `reject` ohne den Text ist
  `failed` („the door may be open“). **Der Körper steht nie im Bericht,
  nur seine Länge** — die Antwort auf eine ANGENOMMENE Anmeldung ist ein
  Sitzungstoken; auch die Meldung „kein Status“ zitiert in diesem Modus
  stdout nicht mehr. curl liefert dafür den Körper und danach den Status
  auf einer eigenen letzten Zeile (`write-out = "\n%{http_code}"`); gelesen
  wird unter dem Deckel für Gastantworten (`Limits::GUEST`, 1 MiB), mehr
  ist `cannot measure`. Ohne das Feld verwirft curl den Körper wie bisher.
  Ein leerer Teilstring ist ein Konfigurationsfehler (er steckt in jedem
  Körper).
- **Strikt: `undeclared_is_failure = true`** auf oberster Ebene (Vorgabe
  `false`). Ein Dienst ohne Probe und ohne Ausnahme ist dann `failed`
  (Exit 1) statt `undeclared`; die Zeile sagt, dass keins von beiden
  deklariert ist.
- `signoff plan` und `signoff rules` nennen alle drei.
- Riegel: `tests/audit_3_b143.rs` (sieben Fälle über Konfigurationstext und
  `app::check`, sechs davon gegen 0.2.0 rot) und Einheitstests in
  `config.rs`, `curlrc.rs` und `checks/factory_login.rs`.

## 0.2.0 — 2026-09-29

Zwei Befunde aus dem IT-Sicherheits-Audit 3 des Homeservers (2026-09-27),
beide `low`. Gemeinsam ist ihnen: Ein übernommener Gast soll weder den Lauf
aufhalten noch den Bericht steuern noch das Urteil fälschen können.

- **B112 — Gastausgaben kommen nur sichtbar in den Bericht, jeder Befehl hat
  eine eigene Grenze.** Ein Urteilstext trägt oft, was ein Gast geliefert
  hat (die erste stderr-Zeile seines curl, Namen aus Authentik), und ging
  bisher roh ins Terminal, ins Journal und über `melden` in Alarmmail und
  ntfy — ein `ESC ] 52` schreibt in vielen Terminals die Zwischenablage.
  `verdict::sanitize` schreibt jetzt jedes Steuerzeichen und jede
  Bidi-Steuerung sichtbar (`\x1b`, `\x0a`, `\u{202e}`) und kürzt auf 300
  Zeichen; angewandt an der einen Stelle, durch die jede Berichtszeile geht
  (`format_line`), und an den Meldungen `control failed`. Dazu hat jeder
  Aufruf eine Frist und einen Lesedeckel je Strom, **je Aufruf gesetzt**
  (`runner::Limits`): was ein Gast liefert (`systemd-run --machine`,
  `nsenter -n … curl`, vantage) 120 s und 1 MiB; Werkzeuge des Wirts (dig,
  curl von `public-path`, machinectl) 120 s und 64 MiB; rustic 600 s und
  64 MiB. Wer länger läuft oder mehr schreibt, wird beendet, die Ausgabe
  verworfen, die Messung heißt `cannot measure`. (Ein erster Wurf hatte
  1 MiB pauschal — rustics Snapshotliste über das ganze Repo, rund 2000
  Snapshots, ist am Server weit größer, und jeder Lauf endete mit Exit 2.
  Die Frist für rustic ist nicht gemessen und deshalb großzügig.) Bisher stand eine Zeitgrenze nur als
  `max-time` in der curl-Konfiguration, die ein Gast-curl ignorieren kann,
  und `systemd-run --wait` wartete ewig. Auch ein Enkel, der die Leitung
  nach dem Ende des Kindes offen hält, hält den Lauf nicht mehr auf.
- **B113 — die Werkskonto-Probe läuft mit dem curl des WIRTS.** Bisher
  führte `factory-login` `/run/current-system/sw/bin/curl` im Gast aus; ein
  Gast mit verändertem Profil sagte immer `401` und damit `ok`. Jetzt:
  `machinectl show <gast> --property=Leader`, dann
  `nsenter -t <leader> -n -- curl -K -` — derselbe Netz-Standpunkt (Adressen,
  Firewall), aber das Programm des Wirts, die Probe weiter nur per stdin.
  Ein Gast ohne Leader oder ein `nsenter`, das den Namensraum nicht betreten
  darf, ist `cannot measure` mit dem Grund.
  **Braucht `CAP_SYS_ADMIN`** (setns) neben `CAP_SYS_PTRACE` — eine Unit,
  die signoff mit weniger Capabilities fährt, muss das nachziehen.
- Riegel: `tests/audit_3.rs` (aus dem Probetest des Auditors, beide Fälle
  gegen 0.1.1 rot) und Einheitstests für Frist, Deckel, Enkel und
  `sanitize`.
