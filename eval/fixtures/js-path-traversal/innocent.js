// eval/fixtures/js-path-traversal/innocent.js
// BACO Eval Fixture: innocent file - serves a fixed bundled asset

const express = require('express');
const path = require('path');
const app = express();

app.get('/logo', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'logo.svg'));
});
