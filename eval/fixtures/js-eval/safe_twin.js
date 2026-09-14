// eval/fixtures/js-eval/safe_twin.js
// BACO Eval Fixture: eval() safe twin - whitelist dispatch, no dynamic code (CWE-95)

const express = require('express');
const app = express();

// SECURE: user input selects from a fixed whitelist of operations;
// no string is ever passed to eval() or new Function().
const operations = {
    double: (n) => n * 2,
    negate: (n) => -n,
    square: (n) => n * n,
};

app.get('/calc', (req, res) => {
    const op = operations[req.query.op];
    const value = Number(req.query.value);
    if (!op || !Number.isFinite(value)) {
        return res.status(400).json({ error: 'invalid input' });
    }
    res.json({ result: op(value) });
});
