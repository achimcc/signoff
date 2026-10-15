# Changelog

## 0.5.1 — 2026-10-16

Audit 4 des Homeservers (2026-10-15).

- **B220: `dns-a`/`dns-aaaa` verlangen genau die Heimadresse.** Bisher genügte
  es, dass sie unter den Antworten war; eine zweite, fremde Adresse daneben
  (ein alter Eintrag, ein Eintrag, den die Zone nicht besitzt) blieb `ok`.
  Jetzt `failed` mit der Zahl der zusätzlichen Adressen, ohne sie zu nennen.
- **B219: Test für die Sperre von qBittorrent.** Mit `reject_body` ist ein
  403 ohne den Abweisungstext (die IP-Sperre nach fünf Fehlversuchen) nicht
  grün. Das Werkzeug konnte das schon; die Konfiguration muss den Text
  deklarieren (oder 403 aus `reject` nehmen).

## 0.5.0 — 2026-10-14

Der VPS wird gekündigt. Die öffentlichen Namen zeigen per A und AAAA
(ddclient) auf den Hausanschluss, der Router leitet :443 per DNAT auf Caddy
im Proxy-Gast weiter (`infra-01`, `10.0.20.11:8443`, v6 ebenso auf :8443).
signoff fragte für `public-path` und den Kanarienvogel weiter den VPS und
kannte für DNS das Ziel `"vps"` — beides misst nach der Kündigung nichts
mehr.

**Bricht die Konfiguration** (`deny_unknown_fields` bleibt: ein altes Feld
ist ein Konfigurationsfehler, kein stilles Weiter-so):

- **Entfernt: `vps_v4`, `vps_v6`** (oben) und **`dns_a`, `dns_aaaa`** (je
  Dienst). Jeder öffentliche Name muss auf den Anschluss zeigen; ein
  anderes Ziel gibt es nicht mehr.
- **Neu: `public_endpoint = "ip:port"`** (IPv4, geprüft wie `backend`) —
  die Adresse, auf die der Router öffentliches :443 weiterleitet.
- **`home_v4_file` und `home_v6_reference` sind Pflicht**, sobald ein
  Dienst `public = true` trägt; fehlt eins, ist es ein
  Konfigurationsfehler.

**`public-path` misst jetzt Caddys öffentlichen Listener**: das curl des
WIRTS im Netz-Namensraum von `caddy_guest` (`nsenter -t <leader> -n`, wie
`factory-login`; die Probe per stdin, nie in argv), `resolve
<host>:<port>:<ip>` auf `public_endpoint`, `https://<host>:<port>/`. Jeder
HTTP-Status ist `ok` („HTTP 302 via 10.0.20.11:8443"). curl-Exit 35 mit
„tlsv1 alert internal error" ist Caddys Ablehnung eines Namens ohne
Zertifikat — `failed`: der Name wird am öffentlichen Listener nicht
bedient. Andere TLS-Fehler und 51/60 bleiben Befunde, alles andere
`cannot measure`. Gemessen am 2026-10-14 im Netz von `infra-01`: echte
Namen 404/302 mit Exit 0, ein erfundener Name
`curl: (35) TLS connect error: error:0A000438:SSL routines::tlsv1 alert
internal error` (jetzt `tests/answers/curl-35-caddy-internal-error.txt`;
die Antwort des VPS, `curl-35-unrecognized.txt`, ist entfernt). Der
**Kanarienvogel** geht denselben Weg und muss genau diesen Befund liefern.

**Was `public-path` NICHT mehr misst:** den Weg von draußen. Den DNAT des
Routers sieht die Probe nicht — sie steht, wo Caddy steht, und der Wirt hat
keine Firewall-Kante zu `10.0.20.11:8443`. Ob die Weiterleitung trägt, ist
eine Frage für eine Probe von außen; vorher bewies das der Weg über den
VPS mit.

**DNS:** `dns-a`/`dns-aaaa` vergleichen immer gegen den Anschluss.
`judge` (feste Adresse) ist entfallen; ein Befund sagt nur noch „weicht
von der Hausadresse ab, Adresse zurückgehalten" — auch die alte
VPS-Adresse wird nicht mehr eigens benannt. Die Referenz für AAAA wird
weiter gegen den Wildcard geprüft, nicht mehr gegen den VPS. Die Regel
„keine Hausadresse in einer Zeile" bleibt unverändert.

## 0.4.0 — 2026-10-11

Seit dem Direktweg des Homeservers (VPS-Ablösung, 2026-10-08/09) zeigen A
und AAAA der meisten öffentlichen Namen auf den Anschluss, ddclient führt
sie nach. signoff erwartete weiter den VPS und meldete jeden Morgen
31× `dns-a` und 31× `dns-aaaa` als Befund — mit der Hausadresse im Text,
also im Journal.

- **Ziel je Familie: `dns_a` / `dns_aaaa = "vps" | "home"`** je Dienst,
  Vorgabe `"vps"` (unverändert). Ein Tippfehler ist ein
  Konfigurationsfehler, kein stilles `"vps"`.
- **`home` für A: `home_v4_file`** — die Datei mit der Außensicht der IPv4
  (auf dem Wirt `/var/lib/hausadresse/v4`). Leer, keine Adresse, privat
  oder die VPS-Adresse: `cannot measure`, ohne den Inhalt zu zitieren.
- **`home` für AAAA: `home_v6_reference`** — der Name, dessen AAAA derselbe
  Updater aus derselben Abfrage schreibt (`nur6.<zone>`). Er muss genau
  eine AAAA tragen, nicht die des VPS und nicht die Antwort des Wildcards
  (`signoff-wildcard-probe.<zone>`): Ein fehlender Referenz-Record wäre
  sonst gleich jedem fehlenden Dienst-Record — gleich, aber falsch grün.
  Gefragt wird der Wildcard, keine Liste von Cloudflare-Bereichen, die
  veralten könnte.
- **Keine Hausadresse in einer Zeile.** `ok` sagt „home address (Quelle)",
  ein Befund nennt den VPS, wenn der Record dorthin zeigt, und sonst nur
  „weicht ab" — eine fremde Adresse an ihrer Stelle kann eine ALTE
  Hausadresse sein. `plan` nennt Datei bzw. Referenznamen.
- Die Sollwerte werden je Lauf einmal geholt und nur, wenn ein
  öffentlicher Dienst sie braucht.

## 0.3.1 — 2026-10-03

Grundhärtung aus dem IT-Sicherheits-Audit 3 des Homeservers (B149), ohne Verhaltensänderung: `unsafe_code` verboten, Flake-Checks `audit` (cargo-audit, Advisory-Datenbank als Flake-Eingang) und `deny` (cargo-deny: Bans, Quellen, Lizenzen), `SECURITY.md`, Renovate.

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
