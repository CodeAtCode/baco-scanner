<?php
/**
 * Lane 4 — Class A fixture: absence of security primitive.
 *
 * Sensitive-state mutation (role escalation) with no capability check
 * or sanitization primitive present in the function body.
 *
 * This is the kind of code `upgrade_for_absent_primitive` should flag:
 * a direct mutation of authentication/authorization state without
 * any guard such as current_user_can(), esc_html(), intval(), wp_kses(), etc.
 */
function escalate_user_role($user_id) {
    global $current_user;

    // No capability check — direct privilege escalation.
    $current_user->role = 'administrator';
    $current_user->caps['administrator'] = true;

    // Persist the escalated role to the database.
    update_user_meta($user_id, 'wp_capabilities', ['administrator' => true]);

    // Additional state mutation without validation.
    $current_user->allcaps = ['administrator' => true, 'edit_posts' => true];
    wp_set_current_user($user_id);
}

/**
 * Another example: modifying post status without capability check.
 */
function publish_draft_post($post_id) {
    global $wpdb;

    // Directly changes post status — no current_user_can('publish_posts') check.
    $wpdb->update(
        $wpdb->posts,
        ['post_status' => 'publish'],
        ['ID' => $post_id]
    );

    clean_post_cache($post_id);
}
