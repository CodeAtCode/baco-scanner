<?php
// eval/fixtures/php-xss/vulnerable.php
// BACO Eval Fixture: Reflected XSS via unescaped echo of $_GET (CWE-79)
// The vulnerability is on line 15 - echo of raw request parameter

/**
 * Render a greeting for the visitor.
 *
 * VULNERABLE: the raw $_GET['name'] value is echoed into the HTML
 * response without htmlspecialchars(), so an attacker can inject
 * arbitrary markup and script (e.g. <script>alert(1)</script>).
 */
function render_greeting() {
    $name = $_GET['name'];
    echo "<h1>Hello, " . $name . "!</h1>";
}
