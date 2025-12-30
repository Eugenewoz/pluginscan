<?php
/**
 * Checksum Command for WP-CLI Plugin Scanner
 */

if (!defined('WP_CLI') || !WP_CLI) {
    return;
}

class Plugin_Checksum_Command {

    /**
     * Base URL for custom checksum libraries.
     */
    private $checksum_repo_url = 'https://raw.githubusercontent.com/eugenewoz/pluginscan/main/plugin-checksums/';

    /**
     * Verifies plugin integrity using custom JSON checksums.
     * * ## OPTIONS
     * * [<plugin>...]
     * : One or more plugin slugs to verify.
     * * [--timeout=<seconds>]
     * : Timeout for fetching checksums. Default: 10
     * * ## EXAMPLES
     * * # Verify a specific plugin
     * $ wp pluginscan checksum elementor-pro
     */
    public function __invoke($args, $assoc_args) {
        $timeout = \WP_CLI\Utils\get_flag_value($assoc_args, 'timeout', 10);
        $installed_plugins = $this->get_installed_plugins();
        
        if (empty($args)) {
            WP_CLI::error("Please provide a plugin slug. Example: wp pluginscan checksum elementor-pro");
            return;
        }

        foreach ($args as $slug) {
            $plugin_file = $this->find_plugin_file_by_slug($slug, $installed_plugins);
            
            if (!$plugin_file) {
                WP_CLI::warning("Plugin '{$slug}' is not installed. Skipping.");
                continue;
            }

            $version = $installed_plugins[$plugin_file]['Version'];
            $checksum_url = $this->checksum_repo_url . "{$slug}-{$version}.json";

            WP_CLI::log("Fetching checksums for {$slug} (v{$version})...");
            
            $response = wp_remote_get($checksum_url, ['timeout' => $timeout]);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                WP_CLI::error("No custom checksum found at: {$checksum_url}");
                continue;
            }

            $checksum_data = json_decode(wp_remote_retrieve_body($response), true);
            if (!$checksum_data || !isset($checksum_data['files'])) {
                WP_CLI::error("Invalid JSON format in checksum file for {$slug}.");
                continue;
            }

            $this->verify_files($slug, $plugin_file, $checksum_data['files']);
        }
    }

    private function verify_files($slug, $plugin_file, $checksum_files) {
        $plugin_dir = WP_PLUGIN_DIR . '/' . (dirname($plugin_file) === '.' ? '' : dirname($plugin_file));
        $errors = [];
        
        $progress = \WP_CLI\Utils\make_progress_bar("Verifying {$slug}", count($checksum_files));

        foreach ($checksum_files as $rel_path => $hashes) {
            $local_path = rtrim($plugin_dir, '/') . '/' . $rel_path;

            if (!file_exists($local_path)) {
                $errors[] = ['file' => $rel_path, 'reason' => 'Missing'];
            } else {
                if (md5_file($local_path) !== $hashes['md5']) {
                    $errors[] = ['file' => $rel_path, 'reason' => 'Mismatch'];
                }
            }
            $progress->tick();
        }
        $progress->finish();

        if (empty($errors)) {
            WP_CLI::success("Checksums match for {$slug}.");
        } else {
            \WP_CLI\Utils\format_items('table', $errors, ['file', 'reason']);
            WP_CLI::error("Integrity check failed for {$slug}.");
        }
    }

    private function find_plugin_file_by_slug($slug, $installed_plugins) {
        foreach ($installed_plugins as $file => $data) {
            $plugin_slug = dirname($file) === '.' ? basename($file, '.php') : dirname($file);
            if ($plugin_slug === $slug) return $file;
        }
        return false;
    }

    private function get_installed_plugins() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        return get_plugins();
    }
}