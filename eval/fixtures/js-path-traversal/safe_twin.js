// eval/fixtures/js-path-traversal/safe_twin.js
// BACO Eval Fixture: Path traversal safe twin - resolved path containment check (CWE-22)

const express = require('express');
const path = require('path');
const app = express();

const BASE_DIR = path.join(__dirname, 'public');

// SECURE: the resolved path is checked against BASE_DIR, so '../'
// sequences that resolve outside the public directory are rejected.
app.get('/download', (req, res) => {
    const requested = path.resolve(BASE_DIR, req.query.file);
    if (requested !== BASE_DIR && !requested.startsWith(BASE_DIR + path.sep)) {
        return res.status(403).send('forbidden');
    }
    res.sendFile(requested);
});
