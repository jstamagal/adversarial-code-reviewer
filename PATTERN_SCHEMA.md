# Pattern Schema Documentation

## Overview

ACR uses a YAML-based pattern format to define attack patterns that detect vulnerabilities in code. Patterns are extensible, type-safe (validated with Pydantic), and support multiple matching strategies.

## Pattern Structure

Every pattern is a YAML file with the following structure:

```yaml
id: unique-pattern-id
name: Pattern Name
description: Human-readable description of the pattern
category: vulnerability-category
severity: critical|high|medium|low|info
cwe: CWE-XXX
owasp: A01:2021-Category
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (kebab-case) |
| `name` | string | Human-readable pattern name |
| `description` | string | Detailed description of the vulnerability |
| `severity` | string | One of: `critical`, `high`, `medium`, `low`, `info` |
| `category` | string | Vulnerability category (e.g., `injection`, `auth`) |
| `attack_vector` | string | Description of how the vulnerability can be exploited |
| `remediation` | object | Remediation information (see below) |
| `detection` | object | Detection templates (see below) |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `cwe` | string | CWE identifier (e.g., `CWE-89`) |
| `owasp` | string | OWASP Top 10 identifier (e.g., `A01:2021-Injection`) |
| `affected_languages` | list | List of programming languages |
| `affected_frameworks` | list | List of frameworks (e.g., `flask`, `django`) |
| `enabled` | boolean | Whether pattern is active (default: `true`) |
| `version` | string | Pattern version (default: `1.0.0`) |
| `author` | string | Pattern author or maintainer |
| `last_modified` | string | ISO 8601 timestamp |
| `tags` | list | Tags for categorization and searching |
| `relationships` | object | Pattern relationships (see below) |
| `dependencies` | list | Required language features or conditions |
| `impact` | object | CIA impact ratings (see below) |
| `references` | list | Reference URLs |
| `examples` | object | Vulnerable and secure code examples |
| `llm_prompts` | object | LLM-specific prompts for analysis |

## Detection Templates

Patterns use one or more template types for detection. Each template type uses a different analysis strategy.

### Static Pattern Templates

Static patterns use regular expressions to match code patterns directly.

```yaml
detection:
  static:
    - pattern: cursor\.execute\(.*\+.*\)
      description: String concatenation in SQL query
      confidence: high
      contexts:
        - function_call
      exclude_patterns:
        - parameterized
```

#### Static Template Fields

| Field | Type | Description |
|-------|------|-------------|
| `pattern` | string (required) | Regular expression to match in code |
| `description` | string | What this pattern matches |
| `confidence` | string | One of: `high`, `medium`, `low` (default: `medium`) |
| `contexts` | list | Code contexts where this applies (e.g., `function_call`) |
| `exclude_patterns` | list | Patterns that exclude this match |

#### Example: Detecting String Concatenation

```yaml
detection:
  static:
    - pattern: cursor\.execute\(.*\+.*\)
      description: String concatenation in SQL query
      confidence: high
```

Matches: `cursor.execute("SELECT * FROM users WHERE id=" + user_id)`

### Data Flow Pattern Templates

Data flow patterns trace taint from untrusted sources to sensitive sinks.

```yaml
detection:
  data_flow:
    - source: request\.(args|form|json|data)
      sink: cursor\.execute
      sanitizers:
        - escape_string
        - quote
      max_distance: 100
      confidence: high
```

#### Data Flow Template Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | string (required) | Regex pattern for taint source (untrusted input) |
| `sink` | string (required) | Regex pattern for taint sink (sensitive operation) |
| `sanitizers` | list | List of regex patterns that sanitize data |
| `max_distance` | integer | Maximum lines between source and sink (default: none) |
| `confidence` | string | One of: `high`, `medium`, `low` (default: `medium`) |

#### Example: SQL Injection via User Input

```yaml
detection:
  data_flow:
    - source: request\.(args|form|json|data)
      sink: cursor\.execute
      sanitizers:
        - escape_string
        - prepared
        - parameterized
      confidence: high
```

Detects when user input reaches SQL execution without sanitization.

### Control Flow Pattern Templates

Control flow patterns analyze the control flow graph (CFG) to detect missing security checks.

```yaml
detection:
  control_flow:
    - entry_point_pattern: @app\.route
      check_pattern: if\s+\.is_authenticated\(
      sensitive_operation_pattern: delete_user\(
      require_check: true
      check_before_operation: true
      check_distance: 20
      confidence: high
```

#### Control Flow Template Fields

| Field | Type | Description |
|-------|------|-------------|
| `entry_point_pattern` | string | Regex pattern for identifying entry points (routes, methods) |
| `check_pattern` | string | Regex pattern for security checks (if statements, guards) |
| `sensitive_operation_pattern` | string (required) | Regex pattern for sensitive operations |
| `require_check` | boolean | Whether a security check is required (default: `true`) |
| `check_before_operation` | boolean | Whether check must be before operation (default: `true`) |
| `check_distance` | integer | Maximum lines between check and operation (default: `50`) |
| `confidence` | string | One of: `high`, `medium`, `low` (default: `medium`) |

#### Example: Missing Authorization Check

```yaml
detection:
  control_flow:
    - check_pattern: if\s+\w+\.is_authenticated\(
      sensitive_operation_pattern: \.delete_user\(
      require_check: true
      check_before_operation: true
      check_distance: 20
      confidence: high
```

Detects sensitive operations without authentication checks before them.

## Remediation

The `remediation` section provides guidance on how to fix the vulnerability.

```yaml
remediation:
  description: Use parameterized queries or prepared statements

  code_before: |
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)

  code_after: |
    query = "SELECT * FROM users WHERE username=%s"
    cursor.execute(query, (username,))
```

### Remediation Fields

| Field | Type | Description |
|-------|------|-------------|
| `description` | string (required) | Remediation description |
| `code_before` | string | Vulnerable code example |
| `code_after` | string | Fixed code example |

You can provide multiple code examples with suffixes:

```yaml
remediation:
  code_before: |
    # Python example
    ...

  code_before_django: |
    # Django-specific example
    ...

  code_before_js: |
    # JavaScript example
    ...
```

## Pattern Relationships

Patterns can define relationships to other patterns:

```yaml
relationships:
  enables:
    - broken-access-control
    - sensitive-data-exposure
  enabled_by:
    - sql-injection
  related:
    - command-injection
    - orm-injection
```

### Relationship Types

| Type | Description |
|------|-------------|
| `enables` | Patterns this pattern enables (creates conditions for) |
| `enabled_by` | Patterns that enable this pattern |
| `related` | Related patterns (similar vulnerabilities) |

These relationships are used in findings to show related vulnerabilities.

## Impact Ratings

The `impact` section rates the vulnerability's impact on the CIA triad:

```yaml
impact:
  confidentiality: high
  integrity: high
  availability: low
```

### Impact Values

Each field can be: `high`, `medium`, `low`, or `none`

## Examples

### Vulnerable Code Examples

```yaml
examples:
  vulnerable:
    - |
      @app.route('/user/<username>')
      def get_user(username):
          query = f"SELECT * FROM users WHERE username='{username}'"
          cursor.execute(query)
```

### Secure Code Examples

```yaml
examples:
  secure:
    - |
      @app.route('/user/<username>')
      def get_user(username):
          query = "SELECT * FROM users WHERE username=%s"
          cursor.execute(query, (username,))
```

## LLM Prompts

Patterns can provide custom prompts for LLM-powered analysis:

```yaml
llm_prompts:
  analyze: |
    Analyze this code for SQL injection vulnerabilities. Focus on:
    1. String concatenation with user input
    2. String formatting in SQL queries
    3. Direct user input in query construction

    Provide:
    - Specific vulnerable lines
    - Attack vectors
    - Recommended fixes

  generate_attack: |
    Generate a SQL injection attack for this code. Show exact payload
    and explain how it works.

  remediation_guidance: |
    Provide specific remediation steps with code examples.
```

## Complete Pattern Example

```yaml
id: sql-injection
name: SQL Injection
category: injection
severity: critical
cwe: CWE-89
owasp: A01:2021-Injection

description: |
  SQL injection occurs when untrusted user input is concatenated into SQL queries
  without proper sanitization or parameterization.

references:
  - https://owasp.org/www-community/attacks/SQL_Injection
  - https://cwe.mitre.org/data/definitions/89.html

affected_languages:
  - python

affected_frameworks:
  - flask
  - django
  - sqlalchemy

tags:
  - injection
  - database
  - authentication-bypass

dependencies:
  - database-connectivity
  - user-input

relationships:
  enables:
    - broken-access-control
    - sensitive-data-exposure
  related:
    - command-injection

impact:
  confidentiality: high
  integrity: high
  availability: low

detection:
  static:
    - pattern: cursor\.execute\(.*\+.*\)
      description: String concatenation in SQL query
      confidence: high

    - pattern: cursor\.execute\(.*%.*\)
      description: String formatting in SQL query
      confidence: medium

  data_flow:
    - source: request\.(args|form|json|data)
      sink: cursor\.execute
      sanitizers:
        - escape_string
        - parameterized
        - prepared

remediation:
  description: Use parameterized queries or prepared statements

  code_before: |
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)

  code_after: |
    query = "SELECT * FROM users WHERE username=%s"
    cursor.execute(query, (username,))

attack_vectors:
  - vector: Authentication Bypass
    payload: "' OR '1'='1"
    description: Bypass authentication by always-true condition

examples:
  vulnerable:
    - |
      @app.route('/user/<username>')
      def get_user(username):
          query = f"SELECT * FROM users WHERE username='{username}'"
          cursor.execute(query)

  secure:
    - |
      @app.route('/user/<username>')
      def get_user(username):
          query = "SELECT * FROM users WHERE username=%s"
          cursor.execute(query, (username,))
```

## Best Practices

1. **Use specific patterns**: Avoid overly broad regex patterns that cause false positives
2. **Combine template types**: Use static, data_flow, and control_flow together for better accuracy
3. **Provide examples**: Always include vulnerable and secure code examples
4. **Document context**: Use `contexts` in static patterns to limit matches to specific situations
5. **Test thoroughly**: Test patterns on real code to verify accuracy
6. **Use sanitizers**: In data flow patterns, list common sanitization functions
7. **Set appropriate confidence**: Use `confidence` to prioritize findings
8. **Reference standards**: Include CWE and OWASP identifiers when applicable
9. **Keep patterns focused**: One pattern per vulnerability type for maintainability
10. **Version your patterns**: Use semantic versioning for pattern updates

## Custom Patterns

To create custom patterns:

1. Create a directory (e.g., `./custom_patterns/`)
2. Add YAML pattern files
3. Configure ACR to use the custom directory:

```yaml
# .acrrc.yaml
patterns:
  custom_patterns: "./custom_patterns"
```

4. Custom patterns can override built-in patterns by using the same `id`

## Pattern Loading

Patterns are loaded by the `PatternLoader` class:

```python
from acr.patterns.loader import PatternLoader

loader = PatternLoader()
patterns = loader.load_patterns(custom_patterns_dir="./custom_patterns")
```

The loader:
- Validates patterns against the schema
- Supports custom patterns that override built-in patterns
- Caches loaded patterns for performance
- Returns a dictionary of patterns keyed by ID

## Pattern Matching

Patterns are matched by the `PatternMatcher` class:

```python
from acr.patterns.matcher import PatternMatcher

matcher = PatternMatcher(patterns=patterns)
findings = matcher.match_patterns(
    ast_data=ast_tree,
    source_code=code,
    file_path="example.py"
)
```

The matcher:
- Supports static, data_flow, and control_flow pattern matching
- Returns `Finding` objects with full context
- Includes related patterns from pattern relationships
- Handles edge cases and errors gracefully

## Testing Patterns

Test your patterns with the test suite:

```python
# tests/unit/test_pattern_matcher.py
def test_my_custom_pattern():
    code = """
    @app.route('/login')
    def login():
        username = request.form.get('username')
        cursor.execute("SELECT * FROM users WHERE username='" + username + "'")
    """

    matcher = create_matcher_with_custom_patterns()
    findings = matcher.match_patterns(ast_data=parse(code), source_code=code)

    assert len(findings) > 0
    assert findings[0].pattern_id == "my-custom-pattern"
```

## Additional Resources

- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Regular Expressions (Python)](https://docs.python.org/3/library/re.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [Built-in Pattern Examples](acr/patterns/library/)
