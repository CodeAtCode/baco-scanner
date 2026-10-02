<?php
// FALSE POSITIVE 2: Protected admin handler - guard 5+ lines after function start
add_action('admin_post_save_config', 'save_config_action');

function save_config_action() {
    // Validate input
    $config = $_POST['config'] ?? [];
    if (empty($config)) {
        wp_die('empty config');
    }
    
    // Additional processing
    $config = array_map('sanitize_text_field', $config);
    
    // The guard is here, several lines down
    check_admin_referer('save_config', 'nonce');
    
    if (!current_user_can('manage_options')) {
        wp_die('forbidden');
    }
    
    update_option('plugin_config', $config);
    wp_redirect(admin_url('options.php'));
}