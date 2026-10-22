# Security notes

- User URLs are parsed as text; no live URL fetching, DNS, redirects, scripts, or downloads are implemented.
- External threat-intelligence APIs are not implemented, so no submitted URL is sent to a provider.
- Request payloads are length-limited. Bulk CSV is limited to 1 MB and 500 rows.
- CORS defaults to the two local Vite origins. Override only with trusted frontend origins.
- API logging omits query values and does not log the submitted URL.
- SQLite stores original URLs locally to support investigation history. Treat query values as potentially sensitive; delete records when no longer needed.
- CSV exports neutralize spreadsheet formula prefixes.
- This local application has no authentication; do not expose it to an untrusted network.
