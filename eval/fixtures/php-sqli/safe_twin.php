<?php
// eval/fixtures/php-sqli/safe_twin.php
// BACO Eval Fixture: SQL Injection safe twin - prepared statement (CWE-89)

require_once 'db.php';

/**
 * Look up a user by the id request parameter.
 *
 * SECURE: uses a prepared statement with a bound parameter, so the
 * user-supplied value can never alter the SQL structure.
 */
function find_user($connection) {
    $user_id = $_GET['id'];
    $stmt = mysqli_prepare($connection, "SELECT * FROM users WHERE id = ?");
    mysqli_stmt_bind_param($stmt, "s", $user_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return mysqli_fetch_assoc($result);
}
