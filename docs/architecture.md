# Architecture

The React client talks to FastAPI over the `/api/v1` JSON API. FastAPI validates HTTP(S) URLs, passes them to an isolated string parser and rule engine, calculates a grouped heuristic score, and persists scan records plus findings in SQLite using SQLAlchemy. Analytics and exports are calculated from saved records. The backend never makes requests to URLs supplied for analysis.

## Data flow

1. Validate scheme, length, characters, host and port.
2. Normalize hostname with Python IDNA handling and extract the registered domain with a bundled public-suffix list.
3. Run independent heuristic rules and capture explanations and evidence.
4. Deduplicate by rule ID and score with reliability weights and category caps.
5. Persist the result and return it to the UI.
