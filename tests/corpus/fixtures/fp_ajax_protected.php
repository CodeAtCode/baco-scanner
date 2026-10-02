<?php
// FALSE POSITIVE 1: Protected wp_ajax handler - guard immediately after function start
add_action('wp_ajax_update_settings', 'update_settings_handler');

function update_settings_handler() {
    check_ajax_referer('update_settings', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_die('forbidden');
    }
    $settings = $_POST['settings'];
    update_option('my_plugin_settings', $settings);
    wp_send_json_success();
}