<?php
// TRUE POSITIVE 1: Unprotected wp_ajax handler - missing CSRF/authorization
add_action('wp_ajax_delete_post', 'delete_post_handler');

function delete_post_handler() {
    $post_id = intval($_POST['post_id']);
    wp_delete_post($post_id, true);
    wp_send_json_success(['deleted' => $post_id]);
}