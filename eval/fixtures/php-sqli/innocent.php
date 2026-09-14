<?php
// eval/fixtures/php-sqli/innocent.php
// BACO Eval Fixture: innocent file - no user input, no SQL

function default_banner(): string {
    $app_name = 'BACO Demo';
    return "Welcome to {$app_name}";
}
