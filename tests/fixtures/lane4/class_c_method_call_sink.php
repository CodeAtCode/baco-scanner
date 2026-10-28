<?php
/**
 * Lane 4 — Class C fixture: method-call sink (CWE-79).
 *
 * User input flows into a template render method with no escaping.
 * This should trigger the `php-template-render-sink-high` semgrep rule.
 */
function render_user_template($template, $user_input) {
    // Directly renders user input — XSS / code injection risk.
    echo $template->render($user_input);
}

/**
 * Another variant using display() method.
 */
function display_user_content($view, $content) {
    // User content passed directly to display without sanitization.
    $view->display($content);
}

/**
 * Variant using execute() method.
 */
function execute_template($tpl, $data) {
    // User data executed as template — potential code injection.
    $tpl->execute($data);
}
