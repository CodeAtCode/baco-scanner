# Authorization Absence Hunt Prompt (BOLA/IDOR/BFLA)

## Hunt Instructions

HUNT FOR MISSING OBJECT-LEVEL AND ROLE-LEVEL AUTHORIZATION ONLY.

Attack class: Broken Object-Level Authorization (BOLA/IDOR), Broken Function-Level Authorization (BFLA)
Task: Analyze this code and report ONLY missing authorization checks in object access or role-gated endpoints.

## Scope — ground model BEFORE judging

BUILD THE GROUND MODEL FIRST. Never assume guard names or authorization patterns.

1. **Identify the router/endpoint declaration style**:
   - How are routes defined? (e.g., `@GetMapping`, `router.get()`, `#[tauri::command]`)
   - What is the canonical path to extract the current principal?
   - Where does user ID/tenant ID enter the call chain?

2. **Find the canonical way this repo reads the current principal**:
   - Look for auth middleware, decorators, or guards
   - Find where `user`, `principal`, `claims`, `identity` is extracted
   - Trace how the principal flows to business logic

3. **Determine the ownership/tenancy model**:
   - What FKs define ownership? (`owner_id`, `tenant_id`, `user_id`, `account_id`)
   - What is the canonical repository/query pattern for ownership checks?
   - Are there helper functions for ownership validation?

4. **Learn the ACTUAL guard vocabulary by reading guard helpers**:
   - Do not assume guard names (e.g., `@RequiresAuth`, `@PreAuthorize`, `checkOwner`)
   - Read the actual guard implementations to understand the vocabulary
   - If guards are inline, identify the pattern (e.g., `if (user.id !== ownerId) return 403`)

5. **If no centralized authz layer exists, raise the prior for missing-authorization findings**:
   - Absence of guards in a repo with sensitive data is itself a finding
   - Default to reporting unguarded object access when no guard pattern exists

## Hunting Rules

1. **Every object access must resolve to an owner check**:
   - `GET /api/users/{id}/profile` → must check `profile.user_id == current_user.id`
   - `PUT /api/tenants/{tid}/settings` → must check `settings.tenant_id == current_tenant.id`
   - If the check is missing → FINDING

2. **"'I can't find a guard in this file' is NOT a finding — it is an instruction to go read the call chain"**:
   - If you see `getUserById(id)` without a guard in this file, trace the caller
   - Look for middleware, decorators, or upstream authorization
   - Only report if the entire call chain lacks authorization

3. **The correctly-scoped sibling branch is SAFE — flagging it is the canonical false positive**:
   - If `GET /api/users/{id}` has an owner check but `DELETE /api/users/{id}` does not, flag DELETE only
   - Do not flag the endpoint that IS properly scoped
   - Compare sibling endpoints to establish the baseline

4. **Default to NOT reporting if any guard chain is unresolved — under-reporting a maybe beats flooding with false positives**:
   - If you cannot trace the full authorization chain, downgrade to NeedsReview
   - If middleware might be present but you cannot confirm, do not report
   - Uncertainty → silence, not noise

5. **Severity test: does the finding defeat an explicit security boundary (acting past an enforced role)?**:
   - Critical: Admin-only endpoint accessible without role check
   - High: User data accessible by another user (IDOR/BOLA)
   - Medium: Non-sensitive data with missing but low-impact authorization
   - Low: Authorization present but slightly weakened (e.g., weak tenant isolation)

## Validation Rules

**Before confirming a finding, verify**:
1. Is there a correctly-scoped sibling endpoint that proves authorization IS possible here?
2. Does the exploit path defeat an explicit security boundary, or is it own-data-only?
3. Are all guard chain links resolved, or is there a gap in the trace?
4. Is the cited file/line/symbol real, or am I inferring from patterns?

**False Positive Guards**:
- If the endpoint is public by design (e.g., `GET /api/public/...`) → NOT a finding
- If ownership is enforced at the database level (e.g., RLS in PostgreSQL) → document, may not need report
- If the "vulnerable" endpoint is never exposed (internal-only, test-only) → NOT a finding

## Return Format

Return JSON array with format:
```json
[
  {
    "severity": "critical|high|medium|low",
    "title": "missing authorization in [endpoint/function] at line [N]",
    "description": "Object/role-level authorization check is missing. The endpoint accesses [resource] without verifying ownership/tenancy/role. Current user can access another user's [resource] by manipulating [parameter]. Ground model: [explain the auth model you found].",
    "line": line_number,
    "cwe_id": "CWE-284|CWE-639",
    "confidence": 0.0-1.0,
    "ground_model": {
      "endpoint_style": "how routes are declared",
      "principal_extraction": "how current user is identified",
      "ownership_model": "FKs that define ownership",
      "guard_vocabulary": "actual guard names/patterns found"
    }
  }
]
```

CRITICAL: ONLY report missing object-level/role-level authorization. Ignore all other attack classes.
Code input will be provided at runtime.

## Scope — stay in your lane

OWNED CLASS: Broken Object-Level Authorization (BOLA/IDOR), Broken Function-Level Authorization (BFLA), missing ownership/tenancy checks on object access.
Anything outside this list is not your finding — if you trip over an adjacent issue (authentication bypass which belongs to auth, injection, XSS), emit it at info severity with title prefix '[handoff: <domain>]' and move on. Staying in lane keeps precision and token cost down.

---

# Authorization Absence Hunt Guide

## Ground Model Building Steps

### Step 1: Router/Endpoint Declaration
- Look for route definitions: `@RequestMapping`, `router.get()`, `#[tauri::command]`
- Identify path parameters: `{id}`, `:userId`, `<tenantId>`
- Note HTTP methods: GET/POST/PUT/DELETE/PATCH

### Step 2: Principal Extraction
- Find auth middleware: `authMiddleware()`, `@AuthenticationPrincipal`
- Look for user context: `req.user`, `ctx.user`, `SecurityContext.getCurrentUser()`
- Trace user ID flow: `userId = req.user.id` → business logic

### Step 3: Ownership Model
- Database schema: `owner_id`, `tenant_id`, `user_id` foreign keys
- Repository patterns: `findByOwnerId()`, `where.tenantId = ?`
- Ownership helpers: `checkOwnership()`, `verifyTenant()`, `isOwner()`

### Step 4: Guard Vocabulary
- Read actual guard implementations (do not assume names)
- Note decorator patterns: `@RequiresRole('ADMIN')`, `@PreAuthorize('#user.id == authentication.principal.id')`
- Note inline patterns: `if (resource.ownerId !== user.id) throw 403`

## Dangerous Patterns by Language

### C/C++ (Web Servers)
- **Missing checks**: File access without user context validation
- **Session handling**: `session->user_id` used without verification
- **Path construction**: `sprintf(path, "/users/%d/data", user_id)` without ownership check

### Python
- **ORM queries**: `User.objects.get(id=user_id)` without checking `user_id == request.user.id`
- **Direct access**: `db.execute("SELECT * FROM posts WHERE id=?", (post_id,))` without owner check
- **FastAPI/Flask**: `get_post(post_id)` without `verify_ownership(post, current_user)`

### Java
- **Repository calls**: `userRepository.findById(id)` without `@PreAuthorize`
- **JPA**: `entityManager.createQuery("FROM Post WHERE id = ?")` without owner filter
- **Spring**: Missing `@RequiresRoles`, `@PreAuthorize` on controller methods

### Go
- **Database queries**: `db.Query("SELECT * FROM users WHERE id=?", id)` without tenant context
- **Handler chains**: Missing middleware for authorization
- **Context**: `ctx.Value("userID")` used without verification

### JavaScript/Node.js
- **ORM**: `Post.findByPk(id)` without `where: { userId: req.user.id }`
- **Direct SQL**: `pool.query('SELECT * FROM posts WHERE id=$1', [id])` without owner check
- **Express**: Route handlers without `requireAuth`, `checkOwnership` middleware

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Public endpoints**: `/api/public/*`, `/health`, `/metrics`
- **System endpoints**: Internal service-to-service communication
- **Database-level enforcement**: Row-Level Security (RLS) policies
- **Ownership in query**: `WHERE id = ? AND owner_id = ?`
- **Middleware protection**: Auth middleware covering entire route group

### Sibling Endpoint Comparison
- If `GET /api/users/{id}` has owner check → use as baseline
- If `DELETE /api/users/{id}` lacks the same check → flag DELETE only
- Do not flag both; the presence of a secure sibling proves the pattern is known

## Chain Opportunities

### Authorization Absence Enables
- **Data Breach**: BOLA allows full dataset exfiltration
- **Account Takeover**: IDOR allows modifying another user's account
- **Privilege Escalation**: BFLA allows admin function access
- **Business Logic Abuse**: Bypass payment, access premium features

### Priority Indicators
- **Critical**: Admin endpoints without role checks, payment bypass
- **High**: User data accessible by other users (PII exposure)
- **Medium**: Non-critical data with missing authorization
- **Low**: Authorization weakened but low-impact (e.g., weak tenant isolation)

---

**Remember**: If you cannot find a guard, do not immediately report. First, read the call chain. If the entire chain lacks authorization, THEN report. If any link is unresolved, downgrade to NeedsReview.