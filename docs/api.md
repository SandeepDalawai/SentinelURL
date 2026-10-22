# API notes

See FastAPI OpenAPI docs at `/docs` when the API is running. Endpoints and query options are listed in the README. Errors use a JSON `detail` field; malformed or unsupported URL strings return HTTP 422. Bulk CSV supports a header named `url` or a one-column file and returns per-row validation failures without aborting the rest of the batch.
