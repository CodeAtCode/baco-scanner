<?php
/**
 * Pay for Payment — real-world shape: handlers registered via add_action,
 * some delegating, some as class methods.
 */
add_action( 'wp_ajax_nopriv_pay4payment_rated', 'dismiss_pointers' );
add_action( 'wp_ajax_pay4payment_rated', 'process_login' );
add_action( 'admin_post_pay4payment', 'generate_web_link' );

function dismiss_pointers() {
    global $wpdb;
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );
}

function process_login() {
    $user = wp_get_current_user();
    if ( ! $user->has_cap( 'manage_options' ) ) {
        wp_die( 'forbidden' );
    }
    do_something();
}

function generate_web_link() {
    return esc_url( add_query_arg( 'rated', '1' ) );
}

function do_something() {
    $wpdb->query( "DELETE FROM orders" );
}

class P4P_Gateway {
    public function enable_access() {
        current_user_can( 'manage_options' );
    }

    public function refund( $id ) {
        $wpdb->update( $wpdb->prefix . 'orders', array( 'id' => $id ) );
    }
}
