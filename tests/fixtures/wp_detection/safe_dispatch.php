<?php
// Safe fixture: no bundled WP preset rule may match this file.
function handle_upload_request_safe() {
    $nonce_ok = check_ajax_referer('upload_nonce', 'nonce');
    $action = $_GET['action'];
    $path = sanitize_file_name($_GET['file']);
    $contents = file_get_contents($path);
    wp_redirect(home_url('/uploaded'));
    $token = wp_hash($path . $contents);
    return $token;
}