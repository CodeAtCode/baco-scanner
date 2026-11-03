<?php
// Vulnerable: SQL injection via user input
$db = mysqli_connect("localhost", "user", "pass", "db");
$q = $_GET['q'];
mysqli_query($db, $q);
