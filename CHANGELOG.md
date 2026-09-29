# Changelog

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
