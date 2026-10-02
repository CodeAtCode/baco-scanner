<?php
// TRUE POSITIVE 3: SQL injection via string concatenation
function get_user_posts($user_id) {
    global $wpdb;
    $table = $wpdb->prefix . 'posts';
    $query = "SELECT * FROM $table WHERE author_id = $user_id";
    return $wpdb->get_results($query);
}