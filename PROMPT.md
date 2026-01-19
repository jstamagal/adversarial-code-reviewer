# Next Agent Task

**Current Phase**: Week 3-4 - Attack Pattern Implementation
**Progress**: 9/20 patterns complete (45%)

## Your ONE Task

Implement **ONE** attack pattern from the list below. Choose the first one you can complete in ~15 minutes.

### Missing Patterns (Pick One)
1. **XXE** (XML External Entity)
2. **Sensitive Data Exposure** 
3. **Broken Access Control**
4. **Security Misconfiguration**
5. **Using Components with Known Vulnerabilities**
6. **Insufficient Logging & Monitoring**
7. **Pickle Deserialization** (Python-specific)
8. **Format String** (Python-specific)
9. **Template Injection** (Python-specific)
10. **Subprocess shell=True** (Python-specific)
11. **YAML.load()** (Python-specific)

### Implementation Steps
1. Create `acr/patterns/library/[pattern_name].yaml`
2. Follow existing format (check `sql_injection.yaml` as example)
3. Include:
   - Pattern metadata (id, name, severity, CWE)
   - Detection rules (AST patterns, function calls to flag)
   - Example vulnerable code
   - Remediation guidance
4. Add basic test in `tests/unit/test_patterns.py` (or create new test file)
5. Run tests: `pytest tests/ -v -o addopts=""`
6. Update `journal/JOURNAL.md` with:
   - Which pattern you implemented
   - Test results
   - Any issues encountered

### Before Exiting
1. ✅ Journal updated with pattern name
2. ✅ Run `git status` - check what files you modified
3. ✅ `git add -A` - stage all changes
4. ✅ `git commit -m "Add [pattern_name] attack pattern"`
5. ✅ Verify commit succeeded with `git log -1 --oneline`
6. ✅ Exit

## Rules
- ONE pattern per agent (keep it focused)
- Must include basic detection logic
- Must test that pattern loads successfully
- **Commit ALL files you modified** (YAML + tests + journal)
- Update journal before exit
- If you get stuck after 15 minutes, document in journal and exit (let next agent try different pattern)

## Resources
- Existing patterns: `acr/patterns/library/*.yaml`
- Pattern schema: `acr/patterns/schema.py`
- TODO.md: Lines 222-260 (full pattern requirements)
- PRD.md: Section 2.1.1 (attack pattern categories)

## Pattern Template
```yaml
id: pattern_id
name: Pattern Name
severity: high|medium|low
category: injection|authentication|access_control|etc
cwe: CWE-XXX
description: |
  Brief description of the vulnerability

detection:
  ast_patterns:
    - node_type: Call
      function_name: dangerous_function
  
  indicators:
    - pattern: "regex or string pattern"
      
examples:
  vulnerable: |
    # Example vulnerable code
    
  secure: |
    # Example secure code

remediation: |
  How to fix this vulnerability
```

---

**Remember**: One pattern, commit everything, exit. Next agent will do the next one.
