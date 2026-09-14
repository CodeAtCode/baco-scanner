<?php
// eval/fixtures/php-xss/innocent.php
// BACO Eval Fixture: innocent file - echoes a constant only

function render_footer() {
    $year = date('Y');
    echo "<footer>Page generated in {$year}</footer>";
}
