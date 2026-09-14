// eval/fixtures/js-eval/vulnerable.js
// BACO Eval Fixture: Code injection via eval() of user input (CWE-95)
// The vulnerability is on line 13 - eval() of req.query payload

const express = require('express');
const app = express();

// VULNERABLE: the query parameter is executed as JavaScript.
// An attacker can submit 'process.mainModule.require("child_process")...'
// as `expr` to run arbitrary code in the server process.
app.get('/calc', (req, res) => {
    const userExpr = req.query.expr;
    const result = eval(userExpr);
    res.json({ result });
});
