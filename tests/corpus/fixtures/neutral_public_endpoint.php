<?php
// NEUTRAL 1: Public read-only endpoint - legitimately no guard
add_action('rest_api_init', function() {
    register_rest_route('my-plugin/v1', '/public-info', array(
        'methods' => 'GET',
        'callback' => 'get_public_info',
    ));
});

function get_public_info() {
    // This endpoint is intentionally public - no auth required
    return new WP_REST_Response([
        'version' => '1.0',
        'name' => 'My Plugin'
    ], 200);
}