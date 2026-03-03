<?php
/**
 * Checksum Command for WP-CLI Plugin Scanner
 *
 * Verifies premium / paid plugin integrity using MD5 checksums stored in
 * local JSON files (plugin-checksums/{slug}-{version}.json).
 *
 * Lookup order
 * ------------
 *  1. Local  → <pluginscan-dir>/plugin-checksums/{slug}-{version}.json
 *  2. Remote → GitHub raw URL (skipped when --local-only is set)
 *
 * JSON file format expected
 * -------------------------
 * {
 *   "plugin":  "elementor-pro",
 *   "version": "3.33.2",
 *   "files": {
 *     "elementor-pro.php":        { "md5": "abc123…", "sha256": "…" },
 *     "assets/css/admin.min.css": { "md5": "def456…" },
 *     …
 *   }
 * }
 *
 * @package  PluginScanner
 * @author   EugeneWoz
 * @license  GPL-2.0+
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
    return;
}

class Plugin_Checksum_Command {

    /**
     * Absolute path to the local checksums directory (no trailing slash).
     * Files must follow the naming convention: {slug}-{version}.json
     *
     * @var string
     */
    private $local_dir;

    /**
     * Base URL for remote checksum files (GitHub raw content).
     * Remote filename format: {slug}-{version}.json
     *
     * @var string
     */
    private $remote_base_url = 'https://raw.githubusercontent.com/eugenewoz/pluginscan/main/plugin-checksums/';

    public function __construct() {
        $this->local_dir = rtrim( __DIR__ . '/plugin-checksums', '/' );
    }

    // =========================================================================
    // Public subcommand: wp pluginscan checksum
    // =========================================================================

    /**
     * Verifies premium plugin integrity using MD5 checksums.
     *
     * Looks for a matching JSON checksum file in the local plugin-checksums/
     * directory first (filename: {slug}-{version}.json). If no local file is
     * found and --local-only is not set, it will attempt to download the file
     * from the configured remote GitHub URL.
     *
     * ## OPTIONS
     *
     * [<plugin>...]
     * : One or more plugin slugs to verify (e.g. elementor-pro).
     *   Required unless --all is used.
     *
     * [--all]
     * : Check every installed plugin that has a checksum file available
     *   (locally or remotely). Plugins without a checksum file are skipped
     *   with a notice.
     *
     * [--local-only]
     * : Only use checksum files from the local plugin-checksums/ directory.
     *   Disables remote fallback entirely.
     *
     * [--format=<format>]
     * : Output format for the list of failed files.
     *   Accepts: table, csv, json, yaml. Default: table
     *
     * [--timeout=<seconds>]
     * : Timeout in seconds used when downloading remote checksum files.
     *   Default: 10
     *
     * ## EXAMPLES
     *
     *     # Verify a single premium plugin
     *     $ wp pluginscan checksum elementor-pro
     *
     *     # Verify several plugins at once
     *     $ wp pluginscan checksum elementor-pro woocommerce-subscriptions
     *
     *     # Verify every installed plugin that has a local checksum file
     *     $ wp pluginscan checksum --all --local-only
     *
     *     # Verify all installed plugins (local first, then remote fallback)
     *     $ wp pluginscan checksum --all
     *
     *     # Output mismatches as JSON
     *     $ wp pluginscan checksum elementor-pro --format=json
     *
     * @param array $args       Positional arguments (plugin slugs).
     * @param array $assoc_args Named flags / options.
     */
    public function __invoke( $args, $assoc_args ) {

        $all        = (bool) \WP_CLI\Utils\get_flag_value( $assoc_args, 'all',        false );
        $local_only = (bool) \WP_CLI\Utils\get_flag_value( $assoc_args, 'local-only', false );
        $format     =        \WP_CLI\Utils\get_flag_value( $assoc_args, 'format',     'table' );
        $timeout    = (int)  \WP_CLI\Utils\get_flag_value( $assoc_args, 'timeout',    10 );

        if ( ! $all && empty( $args ) ) {
            WP_CLI::error(
                "Specify at least one plugin slug, or use --all to check everything.\n\n" .
                "  Examples:\n" .
                "    wp pluginscan checksum elementor-pro\n" .
                "    wp pluginscan checksum --all --local-only"
            );
            return;
        }

        $installed = $this->get_installed_plugins();

        // ── Build the list of slugs to process ───────────────────────────────
        if ( $all ) {
            $slugs = $this->find_checksum_candidates( $installed, $local_only, $timeout );

            if ( empty( $slugs ) ) {
                WP_CLI::warning(
                    'No checksum files found for any installed plugin.' .
                    ( $local_only
                        ? ' (--local-only: only plugin-checksums/ was searched)'
                        : '' )
                );
                return;
            }

            WP_CLI::log( sprintf( 'Found checksum files for %d plugin(s).', count( $slugs ) ) );
        } else {
            $slugs = $args;
        }

        // ── Run verification ──────────────────────────────────────────────────
        $passed  = 0;
        $failed  = 0;
        $skipped = 0;

        foreach ( $slugs as $slug ) {
            $result = $this->verify_plugin( $slug, $installed, $local_only, $timeout, $format );

            if ( $result === 'passed'  ) { $passed++;  }
            if ( $result === 'failed'  ) { $failed++;  }
            if ( $result === 'skipped' ) { $skipped++; }
        }

        // ── Summary (only when more than one plugin was checked) ──────────────
        if ( count( $slugs ) > 1 ) {
            WP_CLI::log( '' );
            WP_CLI::log( sprintf(
                'Checksum summary — Passed: %d  |  Failed: %d  |  Skipped: %d',
                $passed, $failed, $skipped
            ) );
        }

        // Exit non-zero if any plugin failed verification
        if ( $failed > 0 ) {
            WP_CLI::halt( 1 );
        }
    }

    // =========================================================================
    // Core verification logic
    // =========================================================================

    /**
     * Verifies a single plugin by slug.
     *
     * @param  string $slug        Plugin slug (e.g. elementor-pro).
     * @param  array  $installed   Map of plugin_file => plugin_data.
     * @param  bool   $local_only  Skip remote lookup when true.
     * @param  int    $timeout     HTTP timeout in seconds.
     * @param  string $format      WP-CLI output format for the error table.
     * @return string 'passed' | 'failed' | 'skipped'
     */
    private function verify_plugin( $slug, $installed, $local_only, $timeout, $format ) {

        $plugin_file = $this->find_plugin_file_by_slug( $slug, $installed );

        if ( ! $plugin_file ) {
            WP_CLI::warning( "Plugin '{$slug}' is not installed. Skipping." );
            return 'skipped';
        }

        $version = $installed[ $plugin_file ]['Version'];
        $name    = $installed[ $plugin_file ]['Name'];

        WP_CLI::log( '' );
        WP_CLI::log( "── {$name} ({$slug}) v{$version} ──" );

        // Load checksum data (local → remote)
        $load = $this->load_checksum_data( $slug, $version, $local_only, $timeout );

        if ( $load['data'] === null ) {
            if ( $local_only ) {
                WP_CLI::warning(
                    "No local checksum file found for {$slug} v{$version}.\n" .
                    "  Expected file : {$this->local_dir}/{$slug}-{$version}.json\n" .
                    "  (Remote lookup is disabled by --local-only)"
                );
            } else {
                WP_CLI::warning(
                    "No checksum file found for {$slug} v{$version}.\n" .
                    "  Local path checked : {$this->local_dir}/{$slug}-{$version}.json\n" .
                    "  Remote URL checked : {$this->remote_base_url}{$slug}-{$version}.json"
                );
            }
            return 'skipped';
        }

        $file_count = count( $load['data']['files'] );
        WP_CLI::log( "  Source  : {$load['source']}" );
        WP_CLI::log( "  Files   : {$file_count}" );

        // Compare each file
        $errors = $this->compare_files( $slug, $plugin_file, $load['data']['files'] );

        if ( empty( $errors ) ) {
            WP_CLI::success( "All {$file_count} checksums match for {$slug}." );
            return 'passed';
        }

        $error_count = count( $errors );
        WP_CLI::log( "  {$error_count} file(s) failed:" );
        \WP_CLI\Utils\format_items( $format, $errors, [ 'file', 'status', 'expected_md5', 'actual_md5' ] );
        WP_CLI::error( "Integrity check FAILED for {$slug} ({$error_count} file(s) did not match).", false );

        return 'failed';
    }

    /**
     * Compares every file listed in the checksum JSON against the installed copy.
     *
     * @param  string $slug           Plugin slug.
     * @param  string $plugin_file    Relative plugin file path from get_plugins().
     * @param  array  $checksum_files Map of relative_path => { md5, sha256? }.
     * @return array  Rows suitable for WP-CLI table output (empty array = all OK).
     */
    private function compare_files( $slug, $plugin_file, $checksum_files ) {

        // Resolve the plugin's root directory on disk
        $plugin_dir = WP_PLUGIN_DIR . '/' . (
            dirname( $plugin_file ) === '.' ? $slug : dirname( $plugin_file )
        );

        $errors   = [];
        $progress = \WP_CLI\Utils\make_progress_bar(
            "  Verifying {$slug}",
            count( $checksum_files )
        );

        foreach ( $checksum_files as $rel_path => $hashes ) {

            $abs_path = $plugin_dir . '/' . $rel_path;

            if ( ! file_exists( $abs_path ) ) {
                $errors[] = [
                    'file'         => $rel_path,
                    'status'       => 'MISSING',
                    'expected_md5' => $hashes['md5'],
                    'actual_md5'   => '(file not found)',
                ];
            } else {
                $actual_md5 = md5_file( $abs_path );

                if ( $actual_md5 !== $hashes['md5'] ) {
                    $errors[] = [
                        'file'         => $rel_path,
                        'status'       => 'MISMATCH',
                        'expected_md5' => $hashes['md5'],
                        'actual_md5'   => $actual_md5,
                    ];
                }
            }

            $progress->tick();
        }

        $progress->finish();

        return $errors;
    }

    // =========================================================================
    // Checksum file resolution  (local → remote)
    // =========================================================================

    /**
     * Loads and validates the checksum JSON for a plugin.
     *
     * Priority:
     *  1. Local file  → plugin-checksums/{slug}-{version}.json
     *  2. Remote file → $this->remote_base_url/{slug}-{version}.json
     *                   (skipped when $local_only is true)
     *
     * @param  string $slug
     * @param  string $version
     * @param  bool   $local_only
     * @param  int    $timeout
     * @return array { data: array|null, source: string }
     */
    private function load_checksum_data( $slug, $version, $local_only, $timeout ) {

        $filename = "{$slug}-{$version}.json";

        // 1. Try local file
        $local_path = $this->local_dir . '/' . $filename;

        if ( file_exists( $local_path ) ) {
            $data = json_decode( file_get_contents( $local_path ), true );

            if ( $this->is_valid_checksum_data( $data ) ) {
                return [
                    'data'   => $data,
                    'source' => "local  →  {$local_path}",
                ];
            }

            WP_CLI::warning( "Local checksum file is present but invalid JSON: {$local_path}" );
            // Fall through to remote if allowed
        }

        // 2. Remote fallback
        if ( $local_only ) {
            return [ 'data' => null, 'source' => 'none' ];
        }

        $remote_url = $this->remote_base_url . $filename;
        WP_CLI::log( "  No local file — trying remote: {$remote_url}" );

        $response = wp_remote_get( $remote_url, [ 'timeout' => $timeout ] );

        if ( is_wp_error( $response ) ) {
            WP_CLI::warning( "Remote fetch error: " . $response->get_error_message() );
            return [ 'data' => null, 'source' => 'none' ];
        }

        if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
            // 404 is expected when no remote file exists yet — not an error
            return [ 'data' => null, 'source' => 'none' ];
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! $this->is_valid_checksum_data( $data ) ) {
            WP_CLI::warning( "Remote checksum file has invalid structure for {$slug} v{$version}." );
            return [ 'data' => null, 'source' => 'none' ];
        }

        return [
            'data'   => $data,
            'source' => "remote →  {$remote_url}",
        ];
    }

    /**
     * Returns true if $data looks like a valid checksum JSON structure.
     *
     * @param  mixed $data  Decoded JSON value.
     * @return bool
     */
    private function is_valid_checksum_data( $data ) {
        return is_array( $data )
            && isset( $data['plugin'] )
            && isset( $data['version'] )
            && isset( $data['files'] )
            && is_array( $data['files'] )
            && ! empty( $data['files'] );
    }

    // =========================================================================
    // --all helper: discover which installed plugins have a checksum available
    // =========================================================================

    /**
     * Iterates all installed plugins and returns slugs that have a matching
     * checksum file (local first; remote HEAD probe if not local-only).
     *
     * @param  array $installed
     * @param  bool  $local_only
     * @param  int   $timeout
     * @return string[]
     */
    private function find_checksum_candidates( $installed, $local_only, $timeout ) {

        $candidates = [];

        WP_CLI::log( 'Scanning for available checksum files…' );

        foreach ( $installed as $plugin_file => $plugin_data ) {

            $slug    = dirname( $plugin_file ) === '.'
                ? basename( $plugin_file, '.php' )
                : dirname( $plugin_file );
            $version  = $plugin_data['Version'];
            $filename = "{$slug}-{$version}.json";

            // Local check
            if ( file_exists( $this->local_dir . '/' . $filename ) ) {
                WP_CLI::log( "  ✓ {$slug} v{$version}  [local]" );
                $candidates[] = $slug;
                continue;
            }

            // Remote HEAD probe (avoids downloading the whole file just to check)
            if ( ! $local_only ) {
                $remote_url = $this->remote_base_url . $filename;
                $response   = wp_remote_head( $remote_url, [ 'timeout' => $timeout ] );

                if ( ! is_wp_error( $response )
                    && wp_remote_retrieve_response_code( $response ) === 200 ) {
                    WP_CLI::log( "  ✓ {$slug} v{$version}  [remote]" );
                    $candidates[] = $slug;
                }
            }
        }

        return $candidates;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Finds the get_plugins() array key for a given plugin slug.
     *
     * @param  string $slug
     * @param  array  $installed_plugins
     * @return string|false
     */
    private function find_plugin_file_by_slug( $slug, $installed_plugins ) {
        foreach ( $installed_plugins as $file => $data ) {
            $s = dirname( $file ) === '.' ? basename( $file, '.php' ) : dirname( $file );
            if ( $s === $slug ) {
                return $file;
            }
        }
        return false;
    }

    /**
     * Returns all installed plugins, loading the admin helper if needed.
     *
     * @return array
     */
    private function get_installed_plugins() {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        return get_plugins();
    }
}
