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