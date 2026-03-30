# Safe URL Intelligence

Place your trusted allowlist file at:

- `intel/safe_domains_10m.txt`

Expected format:

- One domain or URL per line
- Examples:
  - `google.com`
  - `youtube.com`
  - `https://microsoft.com`

For best results at scale, keep only normalized host/domain values.

The app builds/loads a Bloom filter cache for O(1) average membership checks:

- Cache file: `intel/safe_domains_10m.bloom`
- Metadata: `intel/safe_domains_10m.meta.json`

You can override paths with environment variables:

- `SAFE_URL_SOURCE_FILE`
- `SAFE_URL_BLOOM_FILE`
- `SAFE_URL_META_FILE`
