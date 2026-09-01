# Memory Safety Hunt Prompt

## Hunt Instructions

HUNT FOR MEMORY SAFETY VULNERABILITIES ONLY.

Attack class: Memory Safety (buffer overflows, use-after-free, integer overflows, double-fetch)
Task: Analyze this code and report ONLY memory safety vulnerabilities.

## Bug Pattern Classes

### 1. Length-Subtraction Underflow (size_t a - b when b > a)
- Pattern: `memcpy(dst, src, size_a - size_b)` where b can exceed a
- Validation: Confirm allocation size and index type width from source, not comments
- Impact: Underflow wraps to huge value → buffer overflow
- Example: `len = user_len - header_len; memcpy(buf, data, len);` when user_len < header_len

### 2. Operator-Precedence Length Errors (a & mask + n)
- Pattern: `buf[a & mask + n]` without parentheses
- Validation: Verify operator precedence; `+` binds tighter than `&`
- Impact: Off-by-many access beyond buffer bounds
- Example: `data[i & 0xFF + 16]` reads 16 bytes past intended boundary

### 3. sizeof(*p) vs sizeof(p) Confusion
- Pattern: `malloc(n * sizeof(p))` instead of `malloc(n * sizeof(*p))`
- Validation: Check if p is a pointer; sizeof(p) yields pointer width, not pointee size
- Impact: Underallocation → heap overflow on write
- Example: `int *p = malloc(n * sizeof(p));` allocates n * 8 bytes on 64-bit, not n * 4

### 4. Double-Fetch TOCTOU
- Pattern: Fetch user data twice without validation between fetches
- Validation: Confirm both fetches from user space; check for modification window
- Impact: User modifies data between checks → bypasses safety checks
- Example: `len = copy_from_user(len_ptr); buf = kmalloc(len); copy_from_user(buf, data_ptr);`

### 5. Offset-From-Allocation Off-by-One
- Pattern: `ptr + alloc_size` instead of `ptr + alloc_size - 1`
- Validation: Confirm allocation size and offset calculation; check boundary conditions
- Impact: Write one byte past allocation → heap corruption
- Example: `buf[offset]` where offset == alloc_size (valid indices are 0 to alloc_size-1)

### 6. Audit-The-Incomplete-Fix
- Pattern: Patch applied to one code path but not all variants
- Validation: Confirm fix clamps only one path; search for related code paths
- Impact: Vulnerability persists in unpatched variant
- Example: Length check added to happy path but error-handling path still uses raw value

## Validation Rules

1. **Confirm allocation size and index type width from source not comments**
   - Do not trust comments stating "size is validated"
   - Read the actual allocation and bounds-checking code

2. **Integer overflow in length computation is the finding even without demonstrated crash**
   - `len = a + b` where a+b can overflow is a vulnerability
   - Report the overflow, not just whether it was exploited

3. **A fix clamping only one path is incomplete**
   - If length is clamped in one branch but not another, report the unclamped path
   - Search all control-flow paths to the vulnerable operation

## Dangerous APIs by Language

### C/C++
- **Buffer Operations**: `strcpy`, `strcat`, `sprintf`, `gets`, `scanf` without width
- **Memory Operations**: `memcpy`, `memmove`, `malloc` with unvalidated sizes
- **String Parsing**: `atoi`, `strtol` without overflow checks
- **Format Strings**: `printf(user_input)`, `fprintf(stderr, fmt)` with user-controlled fmt

### Rust (unsafe blocks)
- **Raw Pointers**: `*mut T` dereference without bounds checking
- **Slice Access**: `slice[index]` in unsafe context without validation
- **Transmute**: `std::mem::transmute` with size mismatches
- **Pointer Arithmetic**: `ptr.offset()` with unvalidated offsets

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Bounded Operations**: `strncpy` with proper null termination, `snprintf`
- **Rust Safe Code**: `Vec::push`, `slice.get(index)` (returns Option)
- **Validated Sizes**: `if (len <= MAX) { malloc(len) }` with MAX being reasonable
- **Checked Arithmetic**: `a.checked_add(b).unwrap_or(0)` or `a.saturating_add(b)`

## Chain Opportunities

### Memory Safety Enables
- **Code Execution**: Buffer overflow → overwrite return address / function pointer
- **Privilege Escalation**: Use-after-free → corrupt kernel structures
- **Information Disclosure**: Out-of-bounds read → leak secrets from memory
- **Denial of Service**: Heap corruption → crash or undefined behavior

### Priority Indicators
- **Critical**: Kernel space, authenticated code execution paths, cryptographic buffers
- **High**: User space with user-controlled input, network-facing code
- **Medium**: Internal APIs with limited input control, debug paths
- **Low**: Logging-only paths, development-only code

## Return Format

Return JSON array with format:
[
  {
    "severity": "critical|high|medium|low",
    "title": "memory safety vulnerability title",
    "description": "detailed explanation of the memory safety flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }
]

CRITICAL: ONLY report memory safety vulnerabilities. Ignore all other attack classes.

## Scope — stay in your lane

OWNED CLASS: Memory safety bugs (buffer overflows, use-after-free, double-free, integer overflow in length, off-by-one, TOCTOU in file ops).
Anything outside this list is not your finding — if you trip over an adjacent issue (command injection via system calls, injection via format strings), emit it at info severity with title prefix '[handoff: <domain>]' and move on. Staying in lane keeps precision and token cost down.

Code input will be provided at runtime.