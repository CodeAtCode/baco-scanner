// eval/fixtures/js-path-traversal/vulnerable.js
// BACO Eval Fixture: Path traversal via path.join of req.query (CWE-22)
// The vulnerability is on line 14 - unsanitized user path joined to base dir

const express = require('express');
const path = require('path');
const app = express();

const BASE_DIR = path.join(__dirname, 'public');

// VULNERABLE: '../' sequences in the file parameter escape BASE_DIR,
// letting an attacker read arbitrary files (e.g. ../../../../etc/passwd).
app.get('/download', (req, res) => {
    const requested = path.join(BASE_DIR, req.query.file);
    res.sendFile(requested);
});
