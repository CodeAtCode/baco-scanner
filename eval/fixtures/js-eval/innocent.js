// eval/fixtures/js-eval/innocent.js
// BACO Eval Fixture: innocent file - pure function, no user input

function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
}

module.exports = { clamp };
