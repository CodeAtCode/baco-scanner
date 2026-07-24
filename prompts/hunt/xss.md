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