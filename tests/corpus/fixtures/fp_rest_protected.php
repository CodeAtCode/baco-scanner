<?php
// FALSE POSITIVE 4: Protected REST endpoint
add_action('rest_api_init', function() {
    register_rest_route('my-plugin/v1', '/status', array(
        'methods' => 'GET',
        'callback' => 'get_plugin_status',
    ));
});

function get_plugin_status() {
    wp_verify_nonce($_GET['_wpnonce'], 'plugin_status');
    return new WP_REST_Response(['status' => 'ok'], 200);
}