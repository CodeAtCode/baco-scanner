<?php
// FALSE POSITIVE 3: Protected via helper function call
add_action('wp_ajax_process_payment', 'process_payment_handler');

function process_payment_handler() {
    verify_payment_auth();
    $amount = intval($_POST['amount']);
    $user_id = get_current_user_id();
    process_payment($user_id, $amount);
    wp_send_json_success();
}

function verify_payment_auth() {
    check_ajax_referer('process_payment', 'nonce');
    if (!current_user_can('edit_posts')) {
        wp_die('forbidden');
    }
}