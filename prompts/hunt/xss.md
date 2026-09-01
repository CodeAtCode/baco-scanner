# Cross-Site Scripting (XSS) Vulnerability Hunt Prompt

## Hunt Instructions

HUNT FOR XSS VULNERABILITIES ONLY.

Attack class: Cross-Site Scripting (reflected, stored, DOM-based)
Task: Analyze this code and report ONLY XSS vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: printf("<div>%s</div>", user_input), custom templates without auto-escape
- Python: render_template_string(user_input), Markup(user_input), print(f"<p>{user_input}</p>")
- Java: <%= request.getParameter("q") %>, response.getWriter().println("<div>" + input)
- Go: tmpl.ExecuteTemplate() with user HTML, template.HTML(userInput), fmt.Fprintf(w, "<div>%s</div>", input)
- Node.js: element.innerHTML = userInput, document.write(), dangerouslySetInnerHTML, .html(userInput)

SAFE PATTERNS (DO NOT REPORT):
- Auto-escaping: Go html/template, Django templates with default auto-escape
- Proper encoding: htmlspecialchars(), escapeHtml(), textContent instead of innerHTML
- CSP: default-src 'self' headers
- React: Using children prop instead of dangerouslySetInnerHTML
- Sanitization: DOMPurify.sanitize(), bleach.clean()

BYPASS DETECTION PATTERNS:
- HTML entities: &#60;script&#62;
- Unicode: \u003cscript\u003e
- Case variation: <ScRiPt>
- Event handlers: <img src=x onerror=alert(1)>
- Context escape: "><script>alert(1)</script> in attribute context

CHAIN OPPORTUNITIES:
- XSS → Cookie theft, session hijacking
- DOM XSS → Keylogging, phishing
- Stored XSS → Malware delivery, reconnaissance
- XSS + CSRF → Authenticated action execution

Return JSON array with format:
[
  {
    "severity": "critical|high|medium|low",
    "title": "XSS vulnerability title",
    "description": "detailed explanation of the XSS flaw",
    "line": line_number,
    "cwe_id": "CWE-79",
    "confidence": 0.0-1.0
  }
]

CRITICAL: ONLY report XSS vulnerabilities. Ignore all other attack classes.

## Scope — stay in your lane

OWNED CLASS: Cross-site scripting (reflected, stored, DOM-based), SSTI that leads to XSS.
Anything outside this list is not your finding — if you trip over an adjacent issue (CSRF which is separate, injection, auth bypass), emit it at info severity with title prefix '[handoff: <domain>]' and move on. Staying in lane keeps precision and token cost down.

Code input will be provided at runtime.

---

# Cross-Site Scripting (XSS) Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++ (Web Servers/CGI)
- **HTML Output**: Direct `printf("<div>%s</div>", user_input)` without escaping
- **Template Engines**: Custom template systems without auto-escape
- **JSON Response**: `sprintf(json, "{\"name\": \"%s\"}", user_input)`

### Python
- **Django**: `render(request, 'template.html', {'html': user_input})` without `|safe` consideration
- **Flask**: `render_template_string(f"<div>{user_input}</div>")`, `Markup(user_input)`
- **Direct Output**: `print(f"<p>{request.args.get('q')}</p>")`
- **JSONP**: `jsonp_callback(request.args.get('callback'))` with user-controlled callback

### Java
- **JSP**: `<%= request.getParameter("q") %>` without escaping
- **Servlet**: `response.getWriter().println("<div>" + userInput + "</div>")`
- **Templates**: `freemarker`, `velocity` with user-controlled templates
- **JSON**: `ObjectMapper` writing user input without sanitization

### Go
- **HTML Templates**: `tmpl.ExecuteTemplate(w, "page", map[string]string{"html": userInput})`
- **Direct Output**: `fmt.Fprintf(w, "<div>%s</div>", userInput)`
- **Template.HTML**: `template.HTML(userInput)` bypassing auto-escaping
- **JSON**: `json.Encoder` with user-controlled fields

### JavaScript/Node.js
- **DOM**: `element.innerHTML = userInput`, `document.write(userInput)`
- **jQuery**: `$(userInput).appendTo('body')`, `.html(userInput)`
- **Templates**: `ejs.render(userTemplate)`, `mustache.render(template, data)`
- **React**: `dangerouslySetInnerHTML={{__html: userInput}}`
- **Angular**: `[innerHTML]="userInput"` without `DomSanitizer`

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Auto-Escaping**: Django templates with default auto-escape, Go `html/template` package
- **Proper Encoding**: `htmlspecialchars()`, `escapeHtml()`, `textContent` instead of `innerHTML`
- **Content Security Policy**: Proper CSP headers with `default-src 'self'`
- **React Safety**: Using `children` prop instead of `dangerouslySetInnerHTML`
- **Sanitization Libraries**: `DOMPurify.sanitize(userInput)`, `bleach.clean(userInput)`

## Bypass Detection Patterns

### Encoding Evasion
- **HTML Entities**: `&#60;script&#62;` instead of `<script>`
- **Unicode**: `\u003cscript\u003e`
- **Case Variation**: `<ScRiPt>` to bypass case-sensitive filters
- **Whitespace**: `<script /src=x>`, `<script\tsrc=x>`

### Context-Specific Attacks
- **Attribute Context**: `"><script>alert(1)</script>`
- **JavaScript Context**: `'; alert(1); //`
- **URL Context**: `javascript:alert(1)` in href attributes
- **Event Handlers**: `<img src=x onerror=alert(1)>`

### Filter Bypass
- **Null Bytes**: `<scr%00ipt>` to bypass string matching
- **Double Encoding**: `%253Cscript%253E`
- **Comment Injection**: `<scr<!-- -->ipt>`

## Chain Opportunities

### XSS Enables
- **Session Hijacking**: `document.cookie` theft
- **CSRF**: Triggering authenticated actions via XSS
- **Keylogging**: JavaScript keylogger injection
- **Phishing**: DOM manipulation to create fake login forms
- **Malware Delivery**: Redirecting to malicious sites, drive-by downloads
- **Reconnaissance**: Exfiltrating internal data via XSS

### Priority Indicators
- **Critical**: Stored XSS in admin panels, DOM XSS with cookie access
- **High**: Reflected XSS with authentication context, XSS in sensitive pages
- **Medium**: Stored XSS on public pages, DOM XSS without sensitive data access
- **Low**: XSS in non-critical contexts (error pages, 404 pages)