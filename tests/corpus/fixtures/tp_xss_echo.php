<?php
// TRUE POSITIVE 4: Unescaped echo of request data (XSS)
function display_search_results() {
    $search = $_GET['q'];
    echo "<div class='results'>Search: " . $search . "</div>";
}
add_shortcode('search_results', 'display_search_results');