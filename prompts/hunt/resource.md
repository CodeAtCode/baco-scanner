# Resource Handling Vulnerability Hunt Prompt

## Hunt Instructions

HUNT FOR RESOURCE HANDLING VULNERABILITIES ONLY.

Attack class: Resource Handling (memory safety, integer overflow, DoS)
Task: Analyze this code and report ONLY resource handling vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: malloc(size*count) without overflow check, strcpy/strcat/sprintf without bounds, large stack allocations
- Python: Unbounded list.append(), io.BytesIO() with large data, subprocess.call() blocking, json.loads() massive payloads
- Java: ArrayList.add() without bounds, unbounded thread creation, FileInputStream without try-with-resources, ReDoS in Pattern.compile()
- Go: make([]byte, userControlledSize), go func() without limits, ioutil.ReadAll() unbounded, deep recursion
- Node.js: Unbounded array push, Buffer.alloc(userSize), sync blocking operations, ReDoS in regex.test()

SAFE PATTERNS (DO NOT REPORT):
- Bounded allocation: Size validation before malloc, max limits on collections
- Context cancellation: context.WithTimeout(), signal.NotifyContext()
- Resource pools: Connection pools, thread pools with limits
- Try-with-resources: Python with open(), Java try-with-resources
- Rate limiting: Request throttling, queue limits

BYPASS DETECTION PATTERNS:
- Integer overflow: size*count wrapping, signed to unsigned conversion
- Memory exhaustion: Large JSON payloads, deeply nested structures
- CPU exhaustion: ReDoS patterns ^(a+)+$, infinite loops
- File descriptor leaks: Opening many files without closing
- Goroutine/thread leaks: Creating many concurrent workers

CHAIN OPPORTUNITIES:
- DoS → Service unavailability, crash exploitation
- Integer overflow → Buffer overflow, crash exploits
- Use-after-free → Information leak, code execution
- Race conditions → Privilege escalation, file operation bypass

Return JSON array with format:
[
  {
    "severity": "critical|high|medium|low",
    "title": "resource handling vulnerability title",
    "description": "detailed explanation of the flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }
]

CRITICAL: ONLY report resource handling vulnerabilities. Ignore all other attack classes.

Code input will be provided at runtime.

---

# Resource Handling Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++
- **Memory Allocation**: `malloc(size * count)` without overflow check, `realloc()` without null check
- **Buffer Operations**: `strcpy()`, `strcat()`, `sprintf()` without bounds
- **Integer Overflow**: `int total = count * size;` before allocation
- **File Descriptors**: `open()` without close, missing `close(fd)` on error paths
- **Stack Overflow**: Large stack allocations, deep recursion

### Python
- **Memory**: Unbounded `list.append()` in loops, `io.BytesIO()` with large data
- **Recursion**: Deep recursion without `sys.setrecursionlimit()` check
- **File Handles**: `open(file)` without `with` statement, missing `close()`
- **Subprocess**: `subprocess.call()` blocking indefinitely
- **JSON**: `json.loads()` with massive payloads (DoS)

### Java
- **Memory**: `ArrayList.add()` without bounds, `String.concat()` in loops
- **Threads**: Unbounded thread creation, missing thread pool limits
- **File**: `FileInputStream` without try-with-resources
- **Collections**: `HashMap` with unbounded growth
- **Regex**: Catastrophic backtracking in `Pattern.compile(userInput)`

### Go
- **Memory**: `make([]byte, userControlledSize)`, unbounded slice growth
- **Goroutines**: `go func()` without limits, goroutine leaks
- **File**: `os.Open()` without defer close
- **Buffer**: `ioutil.ReadAll(reader)` with unbounded input
- **Recursion**: Deep recursion without stack check

### JavaScript/Node.js
- **Memory**: Unbounded array push, `Buffer.alloc(userSize)`
- **Event Loop**: Synchronous blocking operations, infinite loops
- **File**: `fs.readFile()` without size limits
- **Async**: Unbounded promise creation, missing error handling
- **Regex**: ReDoS in `regex.test(userInput)`

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Bounded Allocation**: Size validation before `malloc()`, max limits on collections
- **Context Cancellation**: `context.WithTimeout()`, `signal.NotifyContext()`
- **Resource Pools**: Connection pools, thread pools with limits
- **Try-with-Resources**: Python `with open()`, Java try-with-resources
- **Rate Limiting**: Request throttling, queue limits

## Bypass Detection Patterns

### Resource Exhaustion
- **Memory**: Large JSON payloads, deeply nested structures
- **CPU**: ReDoS patterns `^(a+)+$`, infinite loops
- **File Descriptors**: Opening many files without closing
- **Goroutine/Thread**: Creating many concurrent workers
- **Disk**: Unbounded file uploads, log file growth

### Integer Overflow
- **Wraparound**: `size * count` wrapping to small value
- **Negative to Large**: Signed to unsigned conversion
- **Addition Overflow**: `offset + length` exceeding bounds

## Chain Opportunities

### Resource Issues Enable
- **Denial of Service**: Exhausting memory, CPU, file descriptors
- **Crash Exploits**: Buffer overflows from integer overflows
- **Information Leak**: Use-after-free leading to memory disclosure
- **Privilege Escalation**: Race conditions in file operations
- **Bypass**: Resource exhaustion causing fallback to insecure mode

### Priority Indicators
- **Critical**: Integer overflow in allocation, unbounded recursion
- **High**: Unbounded goroutine/thread creation, ReDoS in auth paths
- **Medium**: Missing resource limits in non-critical paths, file handle leaks
- **Low**: Minor memory inefficiencies, non-blocking resource leaks