<?php
// eval/fixtures/php-xss/safe_twin.php
// BACO Eval Fixture: XSS safe twin - htmlspecialchars escaping (CWE-79)

/**
 * Render a greeting for the visitor.
 *
 * SECURE: the user value is passed through htmlspecialchars() so any
 * markup characters are neutralized before reaching the response.
 */
function render_greeting() {
    $name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
    echo "<h1>Hello, " . $name . "!</h1>";
}
