# Insecure Deserialization/Configuration Vulnerability Hunt Prompt

## Hunt Instructions

HUNT FOR INSECURE DESERIALIZATION/CONFIG VULNERABILITIES ONLY.

Attack class: Insecure Deserialization / Configuration
Task: Analyze this code and report ONLY deserialization or config vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: memcpy() from network/buffer without validation, custom binary format parsing
- Python: pickle.loads(user_input), yaml.load(user_input) without SafeLoader, marshal.loads()
- Java: ObjectInputStream.readObject(), xstream.fromXML(), ObjectMapper.readValue() with polymorphic types
- Go: gob.NewDecoder().Decode() with untrusted data, json.Unmarshal() with interface{}
- Node.js: JSON.parse() with __proto__ pollution, yaml.parse() without safe options, msgpack.decode()

SAFE PATTERNS (DO NOT REPORT):
- Safe loaders: yaml.safe_load(), yaml.load(..., SafeLoader)
- Type allowlists: XStream.allowTypesByWildcard(["com.example.safe.*"])
- Schema validation: JSON Schema validation before parsing
- Immutable types: Deserializing only to immutable data structures
- JSON only: Using JSON instead of binary serialization formats

BYPASS DETECTION PATTERNS:
- Gadget chains: Known exploit chains (Apache Commons, Java Serialization)
- Type confusion: Casting to unexpected types after deserialization
- Prototype pollution: {"__proto__": {"admin": true}}
- Polymorphic abuse: Deserializing to unexpected subclasses
- Metadata manipulation: Modifying version/length fields

CHAIN OPPORTUNITIES:
- Deserialization → Remote code execution, auth bypass, privilege escalation
- Config flaws → Credential theft, reconnaissance, bypass, DoS, lateral movement

Return JSON array with format:
[
  {
    "severity": "critical|high|medium|low",
    "title": "deserialization/config vulnerability title",
    "description": "detailed explanation of the flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }
]

CRITICAL: ONLY report deserialization/config vulnerabilities. Ignore all other attack classes.

Code input will be provided at runtime.

---

# Insecure Deserialization/Configuration Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++
- **Serialization**: `memcpy()` from network/buffer without validation
- **Struct Parsing**: `read(fd, &struct, sizeof(struct))` from untrusted source
- **Pickles**: Custom binary format parsing without schema validation
- **Memory**: Deserializing into fixed-size buffers

### Python
- **Pickle**: `pickle.loads(user_input)`, `pickle.load(file)`
- **YAML**: `yaml.load(user_input)` without `SafeLoader`
- **Marshal**: `marshal.loads(user_input)`
- **Shelve**: `shelve.open()` with untrusted data
- **JSON**: `json.loads()` with custom `object_hook` executing code

### Java
- **Serialization**: `ObjectInputStream.readObject()` from untrusted source
- **XStream**: `xstream.fromXML(user_input)` without type allowlist
- **Jackson**: `ObjectMapper.readValue()` with polymorphic types enabled
- **YAML**: `new Yaml().load(user_input)` without safe constructor
- **JSON**: `JSONObject.parse(user_input)` with gadget classes

### Go
- **Gob**: `gob.NewDecoder(reader).Decode(&struct)` with untrusted data
- **JSON**: `json.Unmarshal()` with `interface{}` leading to type confusion
- **Marshal**: Custom marshaling without validation
- **Protobuf**: `proto.Unmarshal()` with unexpected fields

### JavaScript/Node.js
- **JSON**: `JSON.parse(user_input)` with `__proto__` pollution
- **Serialize-JS**: `serialize-javascript` without strict mode
- **YAML**: `yaml.parse(user_input)` without safe options
- **MessagePack**: `msgpack.decode(user_input)` without schema validation

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Safe Loaders**: `yaml.safe_load()`, `yaml.load(..., SafeLoader)`
- **Type Allowlists**: `XStream.allowTypesByWildcard(["com.example.safe.*"])`
- **Schema Validation**: JSON Schema validation before parsing
- **Immutable Types**: Deserializing only to immutable data structures
- **JSON Only**: Using JSON instead of binary serialization formats

## Bypass Detection Patterns

### Deserialization Attacks
- **Gadget Chains**: Known exploit chains (Apache Commons, Java Serialization)
- **Type Confusion**: Casting to unexpected types after deserialization
- **Prototype Pollution**: `{"__proto__": {"admin": true}}`
- **Polymorphic Abuse**: Deserializing to unexpected subclasses
- **Metadata Manipulation**: Modifying version/length fields

### Configuration Issues
- **Hardcoded Secrets**: `SECRET_KEY = "abc123"` in config files
- **Debug Mode**: `DEBUG = True` in production
- **Weak CORS**: `Access-Control-Allow-Origin: *` on sensitive endpoints
- **Excessive Permissions**: `chmod 777`, running as root
- **Insecure Defaults**: SSL verification disabled, weak ciphers

## Chain Opportunities

### Deserialization Enables
- **Remote Code Execution**: Gadget chains leading to `Runtime.exec()`
- **Authentication Bypass**: Deserializing admin session objects
- **Privilege Escalation**: Modifying serialized permission objects
- **Data Tampering**: Altering serialized business logic state
- **Information Disclosure**: Deserializing sensitive configuration

### Config Vulnerabilities Enable
- **Credential Theft**: Hardcoded API keys, database passwords
- **Reconnaissance**: Debug endpoints exposing internal state
- **Bypass**: CORS allowing cross-origin attacks
- **DoS**: Unbounded resource allocation from config
- **Lateral Movement**: Internal network settings exposed

### Priority Indicators
- **Critical**: `pickle.loads()`, `readObject()` from HTTP input, RCE gadget chains
- **High**: YAML unsafe load, hardcoded secrets in repo, debug mode in production
- **Medium**: Prototype pollution potential, weak configuration defaults
- **Low**: Info disclosure in config, missing security headers