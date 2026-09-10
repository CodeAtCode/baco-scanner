# WordPress Detection Fixtures

## Purpose

Hand-written vulnerable/safe PHP fixture pair guarding the `wordpress-plugin` preset's bundled `custom_rules` semgrep detection.

## Provenance

These fixtures are original, hand-written test files created specifically for the baco security scanner's regression suite. They are NOT derived from any external benchmark dataset and carry no license constraints beyond the project's GPL-3.0 terms.

## Expected Rule Matches

### vulnerable_dispatch.php

All four bundled WP preset rules must fire:

- **wp-superglobal-file-read-high** — `$_GET['file']` flows into `file_get_contents()` and `readfile()` (file read sinks)
- **wp-open-redirect-superglobal-medium** — `$_REQUEST['next_url']` flows into `wp_redirect()` (open redirect sink)
- **wp-ajax-dispatch-missing-nonce-high** — `$_GET['action']` used in switch dispatch without prior `check_ajax_referer()` nonce validation
- **php-weak-hash-md5-medium** — `md5()` used for token generation

### safe_dispatch.php

Zero findings expected:

- The AJAX nonce check (`check_ajax_referer`) at function entry exempts this file from the `wp-ajax-dispatch-missing-nonce-high` rule
- Superglobals (`$_GET`, `$_REQUEST`) do NOT flow directly into sinks — they are either sanitized (`sanitize_file_name`) or used with safe alternatives (`home_url()`, `wp_hash()`)
- No file read sinks receive unsanitized superglobal input
- No open redirect sink receives unsanitized superglobal input