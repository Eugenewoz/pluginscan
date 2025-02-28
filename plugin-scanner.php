<?php
/**
 * Plugin Scanner Command for WP-CLI
 * 
 * Scans all WordPress plugins and compares them with WordPress.org API and a custom JSON allowlist
 * to identify potentially suspicious plugins. Also scans filesystem for hidden plugin folders.
 * 
 * @package           PluginScanner
 * @author            EugeneWoz
 * @license           GPL-2.0+
 * 
 * @wordpress-plugin
 * Plugin Name:       WP-CLI Plugin Scanner
 * Plugin URI:        https://github.com/eugenewoz/pluginscan
 * Description:       WP-CLI command to scan plugins and identify suspicious ones not in official repository or custom allowlist.
 * Version:           1.0.0
 * Author:            EugeneWoz
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 */

if (!defined('WP_CLI') || !WP_CLI) {
    return;
}

/**
 * WP-CLI command to scan plugins and identify suspicious ones, with whitelisting capability.
 */
class Plugin_Scanner_Command {

    /**
     * Default custom JSON allowlist URL.
     * 
     * @var string
     */
    private $default_json_url = 'https://raw.githubusercontent.com/eugenewoz/pluginscan/main/allowed-plugins.json';

    /**
     * Default GitHub repository information.
     * 
     * @var array
     */
    private $github_repo = [
        'owner' => 'eugenewoz',
        'repo' => 'pluginscan',
        'file' => 'allowed-plugins.json',
        'branch' => 'main'
    ];

    /**
     * Scans all plugins and compares against WordPress.org API and a custom JSON allowlist.
     * Also scans filesystem for hidden plugin folders.
     * 
     * ## OPTIONS
     * 
     * [--custom-json=<url>]
     * : URL to the custom JSON allowlist file. Default: https://raw.githubusercontent.com/eugenewoz/pluginscan/main/allowed-plugins.json
     * 
     * [--skip-wp-org]
     * : Skip checking plugins against WordPress.org Plugin API
     * 
     * [--skip-filesystem]
     * : Skip scanning filesystem for hidden plugin folders
     * 
     * [--format=<format>]
     * : Output format. Accepts: table, csv, json, count, ids, yaml. Default: table
     * 
     * [--timeout=<seconds>]
     * : Timeout for API requests in seconds. Default: 5
     * 
     * ## EXAMPLES
     * 
     *     # Scan plugins with both WordPress.org API and default custom allowlist
     *     $ wp pluginscan
     * 
     *     # Scan plugins with only custom allowlist (skip WordPress.org API)
     *     $ wp pluginscan --skip-wp-org
     * 
     *     # Skip filesystem scan for hidden plugin folders
     *     $ wp pluginscan --skip-filesystem
     * 
     *     # Scan plugins with custom JSON allowlist URL
     *     $ wp pluginscan --custom-json=https://example.com/custom-allowlist.json
     * 
     *     # Output results as JSON
     *     $ wp pluginscan --format=json
     * 
     * @param array $args       Command arguments.
     * @param array $assoc_args Command options.
     */
    public function __invoke($args, $assoc_args) {
        // Parse arguments
        $custom_json_url = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'custom-json',
            $this->default_json_url
        );
        
        $skip_wp_org = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'skip-wp-org',
            false
        );
        
        $skip_filesystem = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'skip-filesystem',
            false
        );
        
        $format = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'format',
            'table'
        );

        $timeout = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'timeout',
            5
        );

        WP_CLI::log("Starting plugin scan...");
        
        // Get all installed plugins
        $installed_plugins = $this->get_installed_plugins();
        WP_CLI::log(sprintf("Found %d installed plugins.", count($installed_plugins)));
        
        // Create empty suspicious plugins array
        $suspicious_plugins = [];
        
        // Check against WordPress.org API if not skipped
        if (!$skip_wp_org) {
            WP_CLI::log("Checking plugins against WordPress.org Plugin API...");
            $suspicious_plugins = $this->check_against_wp_org($installed_plugins, $timeout);
            WP_CLI::log(sprintf("Found %d plugins not in WordPress.org repository.", count($suspicious_plugins)));
        } else {
            // If skipping WordPress.org check, start with all plugins as suspicious
            $suspicious_plugins = $installed_plugins;
        }
        
        // Fetch and decode the custom JSON allowlist
        WP_CLI::log("Fetching custom allowlist: $custom_json_url");
        $custom_allowed_plugins = $this->fetch_allowed_plugins($custom_json_url, $timeout);
        
        if ($custom_allowed_plugins) {
            WP_CLI::log(sprintf("Loaded %d allowed plugins from custom JSON.", count($custom_allowed_plugins)));
            
            // Filter out plugins that are in the custom allowlist
            $suspicious_plugins = $this->filter_allowed_plugins($suspicious_plugins, $custom_allowed_plugins);
        }
        
        // Prepare items for output
        $items = [];
        
        // Add suspicious registered plugins to items
        foreach ($suspicious_plugins as $plugin_file => $plugin_data) {
            $items[] = [
                'name' => $plugin_data['Name'],
                'slug' => dirname($plugin_file) === '.' ? basename($plugin_file, '.php') : dirname($plugin_file),
                'version' => $plugin_data['Version'],
                'author' => strip_tags($plugin_data['Author']),
                'status' => is_plugin_active($plugin_file) ? 'active' : 'inactive',
                'path' => WP_PLUGIN_DIR . '/' . $plugin_file,
                'type' => 'registered'
            ];
        }
        
        // Scan filesystem for hidden plugin directories if not skipped
        if (!$skip_filesystem) {
            WP_CLI::log("Scanning filesystem for hidden plugin directories...");
            $hidden_plugins = $this->scan_filesystem_for_plugins($installed_plugins, $custom_allowed_plugins);
            
            if (!empty($hidden_plugins)) {
                WP_CLI::log(sprintf("Found %d hidden plugin directories.", count($hidden_plugins)));
                
                // Add hidden plugins to items
                foreach ($hidden_plugins as $hidden_plugin) {
                    $items[] = [
                        'name' => $hidden_plugin['name'],
                        'slug' => $hidden_plugin['slug'],
                        'version' => 'Unknown',
                        'author' => 'Unknown',
                        'status' => 'hidden',
                        'path' => $hidden_plugin['path'],
                        'type' => 'hidden'
                    ];
                }
            } else {
                WP_CLI::log("No hidden plugin directories found.");
            }
        }
        
        // Output results
        if (empty($items)) {
            WP_CLI::success("All plugins are either in the WordPress.org repository or your custom allowlist. No suspicious plugins found.");
            return;
        }
        
        // Format and display output
        $fields = ['name', 'slug', 'version', 'author', 'status', 'path', 'type'];
        
        \WP_CLI\Utils\format_items($format, $items, $fields);
        
        WP_CLI::warning(sprintf("Found %d suspicious plugins.", count($items)));
    }

    /**
     * Adds a plugin to the custom allowlist.
     * 
     * ## OPTIONS
     * 
     * <plugin>
     * : The plugin slug or name to whitelist.
     * 
     * [--github-token=<token>]
     * : GitHub Personal Access Token with repo scope.
     * 
     * [--custom-json=<url>]
     * : URL to the custom JSON allowlist file. Default: https://raw.githubusercontent.com/eugenewoz/pluginscan/main/allowed-plugins.json
     * 
     * [--github-owner=<owner>]
     * : GitHub repository owner. Default: eugenewoz
     * 
     * [--github-repo=<repo>]
     * : GitHub repository name. Default: pluginscan
     * 
     * [--github-branch=<branch>]
     * : GitHub repository branch. Default: main
     * 
     * [--github-file=<file>]
     * : Path to the JSON file in the GitHub repository. Default: allowed-plugins.json
     * 
     * ## EXAMPLES
     * 
     *     # Whitelist a plugin using the installed plugin slug
     *     $ wp pluginscan whitelist elementor-pro
     * 
     *     # Whitelist using a GitHub token for authentication
     *     $ wp pluginscan whitelist elementor-pro --github-token=ghp_xxxxxxxxxxxx
     * 
     *     # Whitelist using a custom GitHub repository
     *     $ wp pluginscan whitelist elementor-pro --github-owner=myuser --github-repo=my-allowlist
     * 
     * @param array $args       Command arguments.
     * @param array $assoc_args Command options.
     */
    public function whitelist($args, $assoc_args) {
        if (empty($args[0])) {
            WP_CLI::error('Please provide a plugin slug or name to whitelist.');
            return;
        }

        $plugin_identifier = $args[0];
        
        // Get GitHub repository information
        $github_owner = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'github-owner',
            $this->github_repo['owner']
        );
        
        $github_repo = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'github-repo',
            $this->github_repo['repo']
        );
        
        $github_branch = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'github-branch',
            $this->github_repo['branch']
        );
        
        $github_file = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'github-file',
            $this->github_repo['file']
        );
        
        $github_token = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'github-token',
            null
        );
        
        // Construct the raw content URL
        $raw_url = "https://raw.githubusercontent.com/{$github_owner}/{$github_repo}/{$github_branch}/{$github_file}";
        
        // Override with custom URL if provided
        $custom_json_url = \WP_CLI\Utils\get_flag_value(
            $assoc_args,
            'custom-json',
            $raw_url
        );
        
        // First, try to find the plugin details
        $plugin_data = $this->find_plugin_by_identifier($plugin_identifier);
        
        if (!$plugin_data) {
            WP_CLI::error("Plugin '{$plugin_identifier}' not found. Make sure it's installed or provide the exact plugin slug.");
            return;
        }
        
        // Extract plugin information
        $plugin_slug = $plugin_data['slug'];
        $plugin_name = $plugin_data['name'];
        
        // Fetch the current allowlist
        WP_CLI::log("Fetching current allowlist...");
        $current_allowlist = $this->fetch_allowed_plugins($custom_json_url, 10);
        
        if ($current_allowlist === false) {
            // Create a new allowlist if it doesn't exist or can't be fetched
            $current_allowlist = [];
        }
        
        // Check if plugin is already in the allowlist
        foreach ($current_allowlist as $allowed_plugin) {
            if (
                (isset($allowed_plugin['slug']) && $allowed_plugin['slug'] === $plugin_slug) ||
                (isset($allowed_plugin['name']) && $allowed_plugin['name'] === $plugin_name)
            ) {
                WP_CLI::success("Plugin '{$plugin_name}' is already in the allowlist.");
                return;
            }
        }
        
        // Add the plugin to the allowlist
        $current_allowlist[] = [
            'slug' => $plugin_slug,
            'name' => $plugin_name
        ];
        
        // Sort the allowlist by slug for better readability
        usort($current_allowlist, function($a, $b) {
            return strcmp($a['slug'], $b['slug']);
        });
        
        // If we have a GitHub token, update the file via GitHub API
        if ($github_token) {
            $this->update_github_file(
                $github_owner,
                $github_repo,
                $github_file,
                $github_branch,
                $github_token,
                $current_allowlist,
                $plugin_name
            );
        } else {
            // Just output the updated allowlist
            WP_CLI::log("Updated allowlist (please add this to your allowlist file):");
            WP_CLI::log(json_encode($current_allowlist, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            WP_CLI::warning("To automatically update the allowlist file, provide a GitHub token with --github-token.");
        }
    }
    
    /**
     * Gets all installed WordPress plugins.
     * 
     * @return array Array of installed plugins.
     */
    private function get_installed_plugins() {
        // Make sure get_plugins() function is available
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        
        return get_plugins();
    }
    
    /**
     * Fetches and decodes the JSON allowlist from the provided URL.
     * 
     * @param string $json_url URL to the JSON allowlist.
     * @param int $timeout Timeout for the request in seconds.
     * @return array|false Array of allowed plugins or false on failure.
     */
    private function fetch_allowed_plugins($json_url, $timeout) {
        $response = wp_remote_get($json_url, ['timeout' => $timeout]);
        
        if (is_wp_error($response)) {
            WP_CLI::warning("Error fetching custom JSON allowlist: " . $response->get_error_message());
            return false;
        }
        
        if (wp_remote_retrieve_response_code($response) !== 200) {
            WP_CLI::warning("Error fetching custom JSON allowlist: HTTP " . wp_remote_retrieve_response_code($response));
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        
        if (empty($body)) {
            WP_CLI::warning("Empty response from JSON allowlist URL.");
            return [];
        }
        
        $allowed_plugins = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            WP_CLI::warning("Error parsing custom JSON allowlist: " . json_last_error_msg());
            return false;
        }
        
        return $allowed_plugins;
    }
    
    /**
     * Checks installed plugins against WordPress.org Plugin API.
     * 
     * @param array $installed_plugins Array of installed plugins.
     * @param int $timeout Timeout for API requests in seconds.
     * @return array Array of suspicious plugins (not found in WordPress.org).
     */
    private function check_against_wp_org($installed_plugins, $timeout) {
        $suspicious_plugins = [];
        $progress = \WP_CLI\Utils\make_progress_bar('Checking plugins against WordPress.org', count($installed_plugins));
        
        foreach ($installed_plugins as $plugin_file => $plugin_data) {
            $plugin_slug = dirname($plugin_file);
            
            // Handle single-file plugins
            if ($plugin_slug === '.') {
                $plugin_slug = basename($plugin_file, '.php');
            }
            
            // Check if plugin exists in WordPress.org repository
            $wp_org_url = "https://api.wordpress.org/plugins/info/1.0/{$plugin_slug}.json";
            $response = wp_remote_get($wp_org_url, ['timeout' => $timeout]);
            
            // If plugin not found in wp.org or error occurred, add to suspicious list
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200 || empty(wp_remote_retrieve_body($response)) || wp_remote_retrieve_body($response) === 'null') {
                $suspicious_plugins[$plugin_file] = $plugin_data;
            }
            
            $progress->tick();
        }
        
        $progress->finish();
        
        return $suspicious_plugins;
    }
    
    /**
     * Filters out plugins that are in the allowed plugins list.
     * 
     * @param array $suspicious_plugins Array of potentially suspicious plugins.
     * @param array $allowed_plugins Array of allowed plugins from JSON.
     * @return array Filtered array of suspicious plugins.
     */
    private function filter_allowed_plugins($suspicious_plugins, $allowed_plugins) {
        $filtered_plugins = [];
        
        foreach ($suspicious_plugins as $plugin_file => $plugin_data) {
            $plugin_slug = dirname($plugin_file) === '.' ? basename($plugin_file, '.php') : dirname($plugin_file);
            
            // Check if the plugin is in the allowlist
            $found = false;
            foreach ($allowed_plugins as $allowed_plugin) {
                // Check if the plugin is in the allowlist using slug, name, or file
                if (
                    (isset($allowed_plugin['slug']) && $allowed_plugin['slug'] === $plugin_slug) ||
                    (isset($allowed_plugin['name']) && $allowed_plugin['name'] === $plugin_data['Name']) ||
                    (isset($allowed_plugin['file']) && $allowed_plugin['file'] === $plugin_file)
                ) {
                    $found = true;
                    break;
                }
            }
            
            if (!$found) {
                $filtered_plugins[$plugin_file] = $plugin_data;
            }
        }
        
        return $filtered_plugins;
    }
    
    /**
     * Finds a plugin by slug or name.
     * 
     * @param string $identifier Plugin slug or name.
     * @return array|false Plugin data or false if not found.
     */
    private function find_plugin_by_identifier($identifier) {
        // Get all installed plugins
        $installed_plugins = $this->get_installed_plugins();
        
        // First try to find by exact slug match
        foreach ($installed_plugins as $plugin_file => $plugin_data) {
            $plugin_slug = dirname($plugin_file) === '.' ? basename($plugin_file, '.php') : dirname($plugin_file);
            
            if ($plugin_slug === $identifier) {
                return [
                    'slug' => $plugin_slug,
                    'name' => $plugin_data['Name'],
                    'file' => $plugin_file
                ];
            }
        }
        
        // Then try to find by name
        foreach ($installed_plugins as $plugin_file => $plugin_data) {
            $plugin_slug = dirname($plugin_file) === '.' ? basename($plugin_file, '.php') : dirname($plugin_file);
            
            if ($plugin_data['Name'] === $identifier) {
                return [
                    'slug' => $plugin_slug,
                    'name' => $plugin_data['Name'],
                    'file' => $plugin_file
                ];
            }
        }
        
        // Try case-insensitive partial match
        foreach ($installed_plugins as $plugin_file => $plugin_data) {
            $plugin_slug = dirname($plugin_file) === '.' ? basename($plugin_file, '.php') : dirname($plugin_file);
            
            if (stripos($plugin_slug, $identifier) !== false || stripos($plugin_data['Name'], $identifier) !== false) {
                return [
                    'slug' => $plugin_slug,
                    'name' => $plugin_data['Name'],
                    'file' => $plugin_file
                ];
            }
        }
        
        return false;
    }
    
    /**
     * Updates a file in a GitHub repository.
     * 
     * @param string $owner GitHub repository owner.
     * @param string $repo GitHub repository name.
     * @param string $file Path to the file in the repository.
     * @param string $branch Repository branch.
     * @param string $token GitHub Personal Access Token.
     * @param array $allowlist Updated allowlist.
     * @param string $plugin_name Name of the plugin being added.
     */
    private function update_github_file($owner, $repo, $file, $branch, $token, $allowlist, $plugin_name) {
        // First, get the current file to get its SHA
        $api_url = "https://api.github.com/repos/{$owner}/{$repo}/contents/{$file}";
        
        $args = [
            'headers' => [
                'Authorization' => "token {$token}",
                'Accept' => 'application/vnd.github.v3+json',
                'User-Agent' => 'WP-CLI Plugin Scanner'
            ]
        ];
        
        // Get the current file to get its SHA
        WP_CLI::log("Fetching current file from GitHub...");
        $response = wp_remote_get($api_url . "?ref={$branch}", $args);
        
        if (is_wp_error($response)) {
            WP_CLI::error("Error fetching file from GitHub: " . $response->get_error_message());
            return;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        // If file doesn't exist, create it
        if ($status_code === 404) {
            WP_CLI::log("File doesn't exist. Creating new file...");
            $sha = null;
        } elseif ($status_code !== 200) {
            WP_CLI::error("Error fetching file from GitHub: HTTP {$status_code}");
            if (isset($body['message'])) {
                WP_CLI::log("GitHub says: " . $body['message']);
            }
            return;
        } else {
            $sha = $body['sha'];
        }
        
        // Prepare the updated content
        $content = json_encode($allowlist, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        
        // Prepare the request body
        $update_data = [
            'message' => "Add {$plugin_name} to allowlist",
            'content' => base64_encode($content),
            'branch' => $branch
        ];
        
        if ($sha) {
            $update_data['sha'] = $sha;
        }
        
        // Update the file
        WP_CLI::log("Updating allowlist file on GitHub...");
        $update_args = array_merge($args, [
            'method' => 'PUT',
            'body' => json_encode($update_data)
        ]);
        
        $update_response = wp_remote_request($api_url, $update_args);
        
        if (is_wp_error($update_response)) {
            WP_CLI::error("Error updating file on GitHub: " . $update_response->get_error_message());
            return;
        }
        
        $update_status = wp_remote_retrieve_response_code($update_response);
        $update_body = json_decode(wp_remote_retrieve_body($update_response), true);
        
        if ($update_status !== 200 && $update_status !== 201) {
            WP_CLI::error("Error updating file on GitHub: HTTP {$update_status}");
            if (isset($update_body['message'])) {
                WP_CLI::log("GitHub says: " . $update_body['message']);
            }
            return;
        }
        
        WP_CLI::success("Plugin '{$plugin_name}' has been added to the allowlist.");
    }

    /**
     * Scans the filesystem for plugin directories that are not registered in WordPress.
     * 
     * @param array $installed_plugins Array of installed plugins.
     * @param array $allowed_plugins Array of allowed plugins from JSON.
     * @return array Array of hidden plugin directories.
     */
    private function scan_filesystem_for_plugins($installed_plugins, $allowed_plugins) {
        $hidden_plugins = [];
        $plugins_dir = WP_PLUGIN_DIR;
        
        // Get list of registered plugin slugs
        $registered_slugs = [];
        foreach ($installed_plugins as $plugin_file => $plugin_data) {
            $slug = dirname($plugin_file);
            if ($slug === '.') {
                $slug = basename($plugin_file, '.php');
            }
            $registered_slugs[] = $slug;
        }
        
        // Get list of allowed plugin slugs
        $allowed_slugs = [];
        if (is_array($allowed_plugins)) {
            foreach ($allowed_plugins as $allowed_plugin) {
                if (isset($allowed_plugin['slug'])) {
                    $allowed_slugs[] = $allowed_plugin['slug'];
                }
            }
        }
        
        // Scan the plugins directory
        if (is_dir($plugins_dir) && $handle = opendir($plugins_dir)) {
            while (false !== ($entry = readdir($handle))) {
                // Skip . and .. directories
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                
                $path = $plugins_dir . '/' . $entry;
                
                // Check if it's a directory
                if (is_dir($path)) {
                    // Check if it's not a registered plugin and not in the allowlist
                    if (!in_array($entry, $registered_slugs) && !in_array($entry, $allowed_slugs)) {
                        // Check if it looks like a plugin directory (contains PHP files or has a specific structure)
                        if ($this->is_likely_plugin_dir($path)) {
                            // Get a name for the plugin
                            $name = $this->get_plugin_name_from_directory($path, $entry);
                            
                            $hidden_plugins[] = [
                                'slug' => $entry,
                                'name' => $name,
                                'path' => $path
                            ];
                        }
                    }
                }
            }
            
            closedir($handle);
        }
        
        return $hidden_plugins;
    }
    
    /**
     * Checks if a directory is likely a plugin directory.
     * 
     * @param string $dir_path Path to the directory.
     * @return bool Whether the directory is likely a plugin directory.
     */
    private function is_likely_plugin_dir($dir_path) {
        // Check for PHP files
        if ($handle = opendir($dir_path)) {
            while (false !== ($entry = readdir($handle))) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                
                // If it has PHP files, it's likely a plugin
                if (pathinfo($entry, PATHINFO_EXTENSION) === 'php') {
                    closedir($handle);
                    return true;
                }
                
                // Check for common plugin directories
                if (is_dir($dir_path . '/' . $entry)) {
                    if (in_array($entry, ['includes', 'admin', 'assets', 'templates', 'vendor', 'src', 'inc'])) {
                        closedir($handle);
                        return true;
                    }
                }
            }
            
            closedir($handle);
        }
        
        // If directory contains specific files that are common in plugins
        $plugin_files = ['index.php', 'readme.txt', 'README.md', 'plugin.php', 'uninstall.php'];
        foreach ($plugin_files as $file) {
            if (file_exists($dir_path . '/' . $file)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Tries to get a plugin name from a directory.
     * 
     * @param string $dir_path Path to the directory.
     * @param string $dir_name Directory name (slug).
     * @return string Plugin name.
     */
    private function get_plugin_name_from_directory($dir_path, $dir_name) {
        // First try to look for a main plugin file
        $potential_plugin_files = [
            "{$dir_name}.php",
            "plugin.php",
            "index.php"
        ];
        
        foreach ($potential_plugin_files as $file) {
            $file_path = $dir_path . '/' . $file;
            if (file_exists($file_path)) {
                $plugin_data = get_plugin_data($file_path, false, false);
                if (!empty($plugin_data['Name'])) {
                    return $plugin_data['Name'];
                }
            }
        }
        
        // If we couldn't find the name, use the directory name
        return ucwords(str_replace(['-', '_'], ' ', $dir_name));
    }
}

// Register the main command
WP_CLI::add_command('pluginscan', 'Plugin_Scanner_Command');
