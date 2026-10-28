# Lane 4 Regression Fixtures

These PHP fixtures support the Lane 4 regression test suite for the baco detection pipeline:

- **Class A (absence detection)**: `class_a_absence.php` — demonstrates a sensitive-state mutation without any security primitive (no `esc_html`, `intval`, `wp_kses`, capability check, etc.). This is the kind of code `upgrade_for_absent_primitive` should flag.
- **Class B (merge-order)**: `class_b_merge_order.php` — illustrates a merge-order logic flaw (CWE-915) where user-controlled fields are merged into an object in an order that allows later fields to overwrite security-relevant earlier fields.
- **Class C (method-call sink)**: `class_c_method_call_sink.php` and `class_c_safe.php` — the vulnerable variant calls `$template->render($user_input)` to trigger the `php-template-render-sink-high` semgrep rule (CWE-79/95); the safe variant uses `htmlspecialchars` and a non-matching method name.

**Note**: Classes A and B are LLM-gated in the current architecture. Their fixtures serve as documentation and enable future e2e tests when an LLM injection point is added. Class C is exercised by the e2e integration test in `tests/integration/lane4_class_c_sink.rs` because it relies on deterministic semgrep rules.
