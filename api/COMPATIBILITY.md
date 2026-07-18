# API-Contract ↔ Server-Kompatibilität

Diese Datei ist die einzige Wahrheitsquelle für die Frage „welche
API-Contract-Version funktioniert mit welchem Server?".

Pflegeregeln:

- Neue Zeile bei jedem Bump von `info.version` (== `API_VERSION`,
  `src/api/mod.rs`). Solange der Contract in der 0er-Reihe liegt, gilt das
  Schema `0.MAJOR.MINOR`: Breaking (Route/Methode oder Feld
  entfernt/umbenannt, Typ geändert, neues Pflichtfeld im Request, geänderte
  Statuscode-/Fehler-Semantik) bumpt die **mittlere** Stelle (z. B.
  0.1.0 → 0.2.0); additive und rein dokumentarische Änderungen bumpen die
  **dritte** Stelle (0.1.0 → 0.1.1).
- **Die Version 1.0.0 vergibt ausschließlich der Autor** — sie markiert den
  bewusst stabilisierten Contract und entsteht niemals als Nebeneffekt einer
  Spec-Umsetzung, egal wie breaking die Änderung ist.
- Server-Releases ohne API-Änderung erfordern keine Änderung — die
  bestehende Range gilt fort.
- Künftige Breaking Changes und Abwärtskompatibilitäts-Aussagen (z. B.
  „Client gegen API 1.x läuft mit Server 0.4–1.9") werden ausschließlich
  hier festgehalten.

| API-Version | Eingeführt mit Server | Kompatible Server-Versionen | Hinweise |
|---|---|---|---|
| 0.1.0 | 0.1.0 | 0.1.0 | Initialer Contract (KV, JSON, Domains, Auth, Metrics) |
| 0.2.0 | 0.1.1 | ≥ 0.1.1 | Breaking (kv/018): `GET` auf einen per `PATCH …/null` genullten Key antwortet 204 statt 404; `set_null` ist ein Update (Key bleibt in Scans sichtbar), kein Soft-Delete mehr |

## Bezug durch das Client-Repo

Git-Tag/Commit von LuraDB pinnen und `api/openapi.json` + diese Datei von
dort beziehen (raw-URL, sparse checkout oder Kopie). Client-seitiger
Codegen (z. B. `openapi-typescript`/`openapi-fetch`, `orval`,
`openapi-generator`) ist Sache des Client-Repos.

**Empfohlene Client-Prüfung beim Verbindungsaufbau:** `GET /version` mit
`Authorization`-Header aufrufen.

- `401` ⇒ Key ungültig — Abbruch mit klarer Fehlermeldung (nützliches
  Pre-Flight-Signal).
- `200` ⇒ kompatibel genau dann, wenn die Major-Stelle übereinstimmt — in
  der 0er-Reihe zusätzlich die **mittlere** Stelle (sie trägt dort die
  Major-Rolle, Schema `0.MAJOR.MINOR`) — **und** `api_version >=`
  einkompilierte Contract-Version (SemVer-Ordnung). Andernfalls Abbruch
  bzw. deutliche Warnung statt produktiver Kommunikation.

## Härtung

`GET /version` antwortet nur mit gültigem API-Key (jede Rolle) —
anonyme Requests erhalten `401`, da exakte Versionsnummern Aufklärungsdaten
für gezielte Angriffe sind. Das ist nur konsistent, wenn exponierte /
produktive Deployments zusätzlich `server.swagger_enabled = false` setzen:
bei `true` liefert `/api-docs/openapi.json` dieselben Versionsdaten
(inkl. `x-luradb-server-version`) ohne jede Auth aus. Der Default bleibt
`true` (Dev-Komfort) — die Umstellung ist Sache der jeweiligen Deployment-
Konfiguration, nicht dieser Spec. `/health` bleibt in jedem Fall public und
enthält niemals Versionsinformationen.
