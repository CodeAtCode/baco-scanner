<?php
// Vulnerable fixture: each bundled WP preset rule must match at least once.
function handle_upload_request() {
    $file_key = 'file';
    $path = $_GET[$file_key];
    $contents = file_get_contents($_GET[$file_key]);
    $asset_key = 'asset';
    readfile($_REQUEST[$asset_key]);
    $next_url_key = 'next_url';
    wp_redirect($_REQUEST[$next_url_key]);
    $action = $_GET['action'];
    switch ($action) {
        case 'upload':
            do_upload($path);
            break;
    }
    $token = md5($path . $contents);
    return $token;
}