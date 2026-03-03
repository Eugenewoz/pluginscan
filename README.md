# WP-CLI Plugin Scanner

A WP-CLI package for identifying suspicious plugins on WordPress installations. Checks installed plugins against the WordPress.org repository and a custom allowlist, scans the filesystem for hidden plugin directories, and verifies the integrity of premium (paid) plugins using MD5 checksums.

## Requirements

- WP-CLI 2.0 or higher
- PHP 7.4 or higher
- WordPress 5.0 or higher

## Installation

```bash
wp package install eugenewoz/pluginscan
```

## Overview

The package exposes three subcommands under `wp pluginscan`:

| Command | Purpose |
|---|---|
| `wp pluginscan scan` | Detect suspicious or unknown plugins |
| `wp pluginscan checksum` | Verify integrity of premium plugins via MD5 checksums |
| `wp pluginscan whitelist` | Add a plugin to your custom allowlist |

---

## Commands

### `wp pluginscan scan`

Scans all installed plugins and flags any that are not found in the WordPress.org repository and are not present in your custom allowlist. Also scans the filesystem for plugin directories that are not registered in WordPress at all (hidden plugins).

```bash
wp pluginscan scan [--custom-json=<url>] [--skip-wp-org] [--skip-filesystem] [--format=<format>] [--timeout=<seconds>]
```

#### Options

| Option | Description | Default |
|---|---|---|
| `--custom-json=<url>` | URL to a custom JSON allowlist file | GitHub hosted allowlist |
| `--skip-wp-org` | Skip checking plugins against the WordPress.org API | false |
| `--skip-filesystem` | Skip scanning the filesystem for hidden plugin directories | false |
| `--format=<format>` | Output format: `table`, `csv`, `json`, `yaml`, `count`, `ids` | `table` |
| `--timeout=<seconds>` | Timeout in seconds for API requests | `5` |

#### Examples

```bash
# Standard scan — checks WordPress.org and the default allowlist
wp pluginscan scan

# Skip the WordPress.org API check (faster, offline-friendly)
wp pluginscan scan --skip-wp-org

# Skip the filesystem scan for hidden plugin directories
wp pluginscan scan --skip-filesystem

# Use your own hosted allowlist instead of the default one
wp pluginscan scan --custom-json=https://example.com/my-allowlist.json

# Output suspicious plugins as JSON (useful for piping or logging)
wp pluginscan scan --format=json
```

#### Output columns

| Column | Description |
|---|---|
| `name` | Plugin display name |
| `slug` | Plugin directory slug |
| `version` | Installed version |
| `author` | Plugin author |
| `status` | `active`, `inactive`, or `hidden` (filesystem only) |
| `path` | Absolute path on disk |
| `type` | `registered` (WordPress-known) or `hidden` (filesystem only) |

---

### `wp pluginscan checksum`

Verifies the integrity of premium (paid) plugins by comparing installed files against known-good MD5 checksums stored in JSON files. This is the equivalent of `wp checksum plugin` but for plugins not available on WordPress.org.

Checksum files are looked up in this order:
1. **Local** — `wp-content/pluginscan-checksums/{slug}-{version}.json`
2. **Remote** — GitHub raw URL (skipped if `--local-only` is set)

Checksum files survive package updates and uninstalls because they live in `wp-content`, outside the WP-CLI package directory.

```bash
wp pluginscan checksum [<plugin>...] [--all] [--local-only] [--format=<format>] [--timeout=<seconds>]
```

#### Options

| Option | Description | Default |
|---|---|---|
| `<plugin>...` | One or more plugin slugs to verify | — |
| `--all` | Verify every installed plugin that has a checksum file available | false |
| `--local-only` | Only use local checksum files, skip remote lookup entirely | false |
| `--format=<format>` | Output format for failed files: `table`, `csv`, `json`, `yaml` | `table` |
| `--timeout=<seconds>` | Timeout in seconds for remote checksum file downloads | `10` |

#### Examples

```bash
# Verify a single premium plugin
wp pluginscan checksum elementor-pro

# Verify multiple plugins at once
wp pluginscan checksum elementor-pro woocommerce-subscriptions

# Verify all installed plugins that have a checksum file (local or remote)
wp pluginscan checksum --all

# Verify all plugins using only your own local checksum files — no network calls
wp pluginscan checksum --all --local-only

# Output any mismatched files as JSON
wp pluginscan checksum elementor-pro --format=json
```

## License

GPL-2.0+. See [LICENSE](LICENSE) for details.
