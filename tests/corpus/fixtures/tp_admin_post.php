<?php
// TRUE POSITIVE 2: Unprotected admin action handler
add_action('admin_post_flush_cache', 'flush_cache_action');

function flush_cache_action() {
    global $wpdb;
    $wpdb->query("TRUNCATE TABLE wp_cache");
    wp_redirect(admin_url('options-general.php'));
}