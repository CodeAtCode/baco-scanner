<?php
/**
 * Lane 4 — Class C safe fixture: no method-call sink.
 *
 * This file should NOT trigger any findings because it uses
 * htmlspecialchars for escaping and calls render_static() which
 * is not matched by the php-template-render-sink-high rule.
 */
function safe_render($template, $user_input) {
    // Properly escape user input before rendering.
    $escaped = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
    echo $template->render_static($escaped);
}

/**
 * Another safe variant using esc_html().
 */
function safe_display($view, $content) {
    $safe_content = esc_html($content);
    $view->display_safe($safe_content);
}
