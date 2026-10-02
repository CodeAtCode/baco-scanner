<?php
// NEUTRAL 2: Function name in title cannot be resolved (hallucinated handler)
add_action('wp_ajax_real_handler', 'real_handler');

function real_handler() {
    // Actual handler exists
    wp_send_json(['ok' => true]);
}

// The finding title references "nonexistent_function()" which does not exist