<?php
// eval/fixtures/php-sqli/vulnerable.php
// BACO Eval Fixture: SQL Injection via $_GET concatenation (CWE-89)
// The vulnerability is on line 16 - $_GET value concatenated into SQL

require_once 'db.php';

/**
 * Look up a user by the id request parameter.
 *
 * VULNERABLE: the raw $_GET['id'] value is concatenated into the SQL
 * statement, so an attacker can inject arbitrary SQL (e.g. ' OR 1=1 --).
 */
function find_user($connection) {
    $user_id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = '" . $user_id . "'";
    $result = mysqli_query($connection, $query);
    return mysqli_fetch_assoc($result);
}
