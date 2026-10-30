# AI Remediation Suggestion for JavaScript SQL/NoSQL Injection in search endpoint

**Target File:** `routes/search.ts`
**Scanner Source:** `Semgrep`

### Root Cause Analysis:
Direct concatenation of untrusted user input into the query string bypasses ORM sanitization.

### Proposed Code Fix:
```yaml
// Use parameterized query instead of string concatenation
models.sequelize.query('SELECT * FROM Products WHERE name LIKE :query', {
  replacements: { query: `%${criteria}%` }
})
```
