# Scaffolding Brief for Implementation Agent

**Date**: 2025-01-19  
**Status**: Ready for Implementation  
**Confidence Level**: 99%

## Executive Summary

The Adversarial Code Reviewer (ACR) is a security tool that flips the code review paradigm - instead of offering helpful suggestions, it actively attacks your code like an adversary would. Think of it as an AI red-teamer for your codebase.

After 5 agent review cycles (Agents 0-4), the PRD and TODO are comprehensive, consistent, and ready for implementation. No blockers exist.

---

## What Has Been Completed

### Planning Documents
1. **PRD.md** (Product Requirements Document)
   - 15 comprehensive sections covering features, architecture, phases, metrics, security, legal, enterprise, and more
   - Zero ambiguity on technical decisions
   - All features detailed with acceptance criteria

2. **TODO.md** (Implementation Tasks)
   - 400+ specific, actionable tasks
   - Organized by 5 phases (44-54 weeks total)
   - Each task has clear acceptance criteria
   - Comprehensive test coverage for each component

3. **Agent Journals** (AGENT0-4_JOURNAL.md)
   - Complete audit trail of all planning decisions
   - Rationale for technical choices
   - Alternative approaches considered
   - All gaps identified and addressed

---

## Core Value Proposition

**Traditional Code Review**: "Here's what you could improve"  
**Adversarial Code Review**: "Here's how I can exploit your code"

ACR forces defensive thinking during development by:
- Finding unintended behaviors through adversarial testing
- Breaking edge cases systematically
- Abusing features in unanticipated ways
- Understanding and subverting business logic
- Generating property-based tests that stress-test assumptions
- Creating multi-step attack scenarios

---

## Technical Architecture Summary

### Technology Stack
- **Core Language**: Python 3.8+
- **Parsing**: tree-sitter (multi-language AST parsing)
- **LLM Integration**: Claude 3.5 Sonnet (primary), GPT-4 (alternative)
- **Analysis**: networkx (CFG/DFG), astroid (Python AST analysis)
- **CLI Framework**: Click
- **Testing**: pytest
- **Configuration**: YAML-based

### Architecture Components
```
┌─────────────┐
│   CLI       │ → User Interface
└──────┬──────┘
       │
┌──────▼──────────────────────────────────┐
│   Code Analysis Engine                  │
│  ┌────────┐  ┌────────┐  ┌──────────┐  │
│  │  AST   │→ │  CFG   │→ │   DFG    │  │
│  │ Parser │  │Builder │  │ Builder  │  │
│  └────────┘  └────────┘  └──────────┘  │
└──────┬──────────────────────────────────┘
       │
┌──────▼──────────────────────────────────┐
│   Attack Pattern Matcher                │
│  - OWASP Top 10                         │
│  - Language-specific patterns           │
│  - Framework-specific patterns          │
└──────┬──────────────────────────────────┘
       │
┌──────▼──────────────────────────────────┐
│   LLM-Powered Intelligence              │
│  - Business logic understanding         │
│  - Multi-step attack generation         │
│  - Context-aware analysis               │
└──────┬──────────────────────────────────┘
       │
┌──────▼──────────────────────────────────┐
│   Reporting Engine                      │
│  - Markdown, JSON, SARIF formats        │
│  - Interactive CLI output               │
│  - Severity scoring                     │
└─────────────────────────────────────────┘
```

---

## Phase 1 MVP Scope (12-14 weeks)

**Goal**: Deliver a working Python analyzer with core attack patterns

### What's IN for MVP:
- **Python Language Support**: AST, CFG, DFG analysis
- **Flask Framework**: Framework-specific patterns
- **20 Core Attack Patterns**: SQL injection, XSS, CSRF, command injection, auth bypass, etc.
- **LLM Integration**: Claude/GPT-4 for intelligent attacks
- **CLI**: Scan, report, config commands
- **Configuration**: YAML-based .acrrc.yaml
- **Reporting**: Markdown and JSON formats
- **Basic CI/CD**: Exit codes for CI integration

### What's OUT of MVP:
- ❌ JavaScript/TypeScript (Phase 2)
- ❌ Property-based test generation (Phase 2)
- ❌ IDE extensions (Phase 3)
- ❌ GitHub Actions integration (Phase 3)
- ❌ Java/Go/Rust support (Phase 4+)
- ❌ Enterprise features (RBAC, SSO) (Phase 5)

---

## Critical Pre-Implementation Tasks (Week 0)

Before scaffolding code, complete these legal/compliance tasks:

1. **Choose Software License**
   - Recommendation: MIT License (permissive, simple)
   - Alternative: Apache 2.0 (patent protection)
   - Create LICENSE file

2. **Write Data Privacy Policy**
   - Clarify: Code is analyzed locally by default
   - LLM API calls are opt-in with clear warnings
   - Document data handling for GDPR/CCPA compliance

3. **Write Terms of Service / Acceptable Use Policy**
   - Purpose: Defensive security, education, remediation
   - Prohibited: Malicious use, unauthorized penetration testing
   - Liability disclaimers

4. **Create Vulnerability Disclosure Policy**
   - Process for reporting 0-day vulnerabilities found in user code
   - Responsible disclosure guidelines
   - Security contact: security@[your-domain]

5. **Create Contributor License Agreement (CLA)**
   - Required for attack pattern contributions
   - Ensures proper licensing of community contributions

---

## Phase 1 Implementation Priorities

### Weeks 1-2: Foundation
- Project structure and scaffolding
- Configuration system (.acrrc.yaml)
- Logging infrastructure
- CLI framework (Click)
- Error handling strategy

### Weeks 3-4: Python Analysis Engine
- tree-sitter integration for Python
- AST parsing and traversal
- CFG (Control Flow Graph) construction
- DFG (Data Flow Graph) construction
- Taint tracking foundation

### Weeks 5-6: Attack Pattern System
- Pattern schema design (YAML-based)
- Pattern loader and validator
- Pattern matcher (static analysis)
- First 10 core patterns implemented

### Weeks 7-8: LLM Integration
- Sensitive data redaction (BEFORE sending to LLM)
- LLM client (Claude/OpenAI)
- Prompt engineering for attacks
- LLM caching system
- Cost estimation

### Weeks 9-10: Reporting & CLI
- Finding data structures
- Markdown report generation
- JSON report generation
- CLI commands (scan, report, init)
- Exit code handling

### Weeks 11-12: Polish & Testing
- Interactive mode basics
- Flask-specific patterns (10 additional patterns)
- Comprehensive testing (unit, integration, e2e)
- Documentation (README, CLI help, basic guides)
- Performance benchmarking

### Weeks 13-14: Buffer & Release Prep
- Bug fixes from testing
- Performance optimization
- PyPI packaging
- MVP release preparation

---

## Key Technical Decisions & Rationale

### Why Python?
- Rich ecosystem for parsing (tree-sitter, astroid)
- Excellent LLM client libraries
- Strong type support (Pydantic)
- Good CLI framework (Click)
- Target audience (Python developers) aligns

### Why tree-sitter?
- Language-agnostic (supports 40+ languages)
- Fast incremental parsing
- Error recovery (handles malformed code)
- Community-maintained grammars

### Why Hybrid Approach (Static + LLM)?
- Static analysis: Fast, deterministic, handles patterns well
- LLM: Intelligent, context-aware, understands business logic
- Hybrid: Best of both worlds - speed + intelligence

### Why Phased Implementation?
- Early feedback (MVP in 12-14 weeks)
- Risk mitigation (validate core value before expanding)
- Resource efficiency (focus on highest-value features first)
- Market validation (test with Python community before expanding to other languages)

---

## Performance & Quality Metrics

### Performance Targets
- **Analysis Speed**: 1000 LOC/minute (simple code), 100 LOC/minute (complex code)
- **Startup Time**: < 2 seconds (cold start), < 500ms (warm start)
- **Memory Usage**: < 500MB for 10k LOC codebase
- **LLM Response Time**: < 5 seconds per LLM call

### Quality Targets
- **False Positive Rate**: < 15% (industry standard: 20-30%)
- **False Negative Rate**: < 20% (against OWASP Benchmark)
- **Pattern Coverage**: 90% of OWASP Top 10 vulnerabilities
- **Test Coverage**: > 80% (unit + integration)

### User Experience Targets
- **Setup Time**: < 5 minutes (install to first scan)
- **First Scan**: < 2 minutes (small Flask app)
- **Configuration**: < 10 minutes (basic .acrrc.yaml)

---

## File Structure for Scaffolding

```
adversarial-code-reviewer/
├── LICENSE                    # MIT or Apache 2.0
├── README.md                  # Project overview
├── CONTRIBUTING.md            # Contribution guidelines
├── SECURITY.md                # Vulnerability disclosure policy
├── pyproject.toml             # Poetry configuration
├── setup.py                   # Package setup
├── .gitignore
├── .acrrc.yaml.example        # Example configuration
│
├── acr/                       # Main package
│   ├── __init__.py
│   ├── __main__.py            # CLI entry point
│   │
│   ├── cli/                   # CLI commands
│   │   ├── __init__.py
│   │   ├── scan.py
│   │   ├── report.py
│   │   ├── init.py
│   │   └── config.py
│   │
│   ├── config/                # Configuration management
│   │   ├── __init__.py
│   │   ├── loader.py
│   │   ├── validator.py
│   │   └── schema.py
│   │
│   ├── core/                  # Core analysis engine
│   │   ├── __init__.py
│   │   ├── analyzer.py        # Main analyzer
│   │   ├── ast_parser.py      # AST parsing (tree-sitter)
│   │   ├── cfg_builder.py     # Control Flow Graph
│   │   ├── dfg_builder.py     # Data Flow Graph
│   │   └── taint_tracker.py   # Taint analysis
│   │
│   ├── patterns/              # Attack patterns
│   │   ├── __init__.py
│   │   ├── loader.py          # Load patterns from YAML
│   │   ├── matcher.py         # Pattern matching engine
│   │   ├── schema.py          # Pattern schema definition
│   │   └── library/           # Pattern library
│   │       ├── sql_injection.yaml
│   │       ├── xss.yaml
│   │       ├── csrf.yaml
│   │       └── ...
│   │
│   ├── llm/                   # LLM integration
│   │   ├── __init__.py
│   │   ├── client.py          # LLM client (Claude/OpenAI)
│   │   ├── prompts.py         # Prompt templates
│   │   ├── redaction.py       # Sensitive data redaction
│   │   └── cache.py           # LLM response caching
│   │
│   ├── reporters/             # Report generation
│   │   ├── __init__.py
│   │   ├── markdown.py
│   │   ├── json.py
│   │   └── base.py
│   │
│   ├── models/                # Data models (Pydantic)
│   │   ├── __init__.py
│   │   ├── finding.py
│   │   ├── pattern.py
│   │   └── config.py
│   │
│   └── utils/                 # Utilities
│       ├── __init__.py
│       ├── logger.py
│       ├── errors.py
│       └── helpers.py
│
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── conftest.py            # Pytest fixtures
│   │
│   ├── unit/                  # Unit tests
│   │   ├── test_ast_parser.py
│   │   ├── test_cfg_builder.py
│   │   ├── test_pattern_matcher.py
│   │   └── ...
│   │
│   ├── integration/           # Integration tests
│   │   ├── test_full_scan.py
│   │   ├── test_llm_integration.py
│   │   └── ...
│   │
│   ├── e2e/                   # End-to-end tests
│   │   ├── test_cli.py
│   │   └── ...
│   │
│   └── fixtures/              # Test fixtures
│       ├── vulnerable_apps/   # Sample vulnerable apps
│       │   ├── flask_sqli/
│       │   ├── flask_xss/
│       │   └── ...
│       └── secure_apps/       # Sample secure apps
│
├── docs/                      # Documentation
│   ├── getting-started.md
│   ├── cli-reference.md
│   ├── configuration.md
│   ├── pattern-reference.md
│   └── architecture.md
│
└── scripts/                   # Development scripts
    ├── install-grammars.sh    # Install tree-sitter grammars
    ├── run-benchmarks.sh
    └── setup-dev.sh
```

---

## Dependencies to Install (Phase 1)

### Core Dependencies
```toml
[tool.poetry.dependencies]
python = "^3.8"
click = "^8.1"              # CLI framework
pydantic = "^2.0"           # Data validation
tree-sitter = "^0.20"       # Parser
tree-sitter-python = "^0.20"
pyyaml = "^6.0"             # Configuration
networkx = "^3.0"           # Graph algorithms (CFG/DFG)
astroid = "^3.0"            # Python AST analysis
anthropic = "^0.21"         # Claude API
openai = "^1.0"             # OpenAI API (alternative)
rich = "^13.0"              # CLI formatting
diskcache = "^5.6"          # LLM response caching
jinja2 = "^3.1"             # Report templating
```

### Dev Dependencies
```toml
[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
pytest-cov = "^4.1"
black = "^24.0"
ruff = "^0.2"
mypy = "^1.8"
pre-commit = "^3.6"
```

---

## Attack Pattern Categories (20 for MVP)

### Injection Attacks (8 patterns)
1. SQL Injection (SQLAlchemy, raw SQL)
2. NoSQL Injection (MongoDB)
3. Command Injection (subprocess, os.system)
4. Template Injection (Jinja2, Flask templates)
5. XPath Injection
6. LDAP Injection
7. Header Injection (HTTP headers)
8. Log Injection

### Authentication & Authorization (4 patterns)
9. Broken Authentication (weak passwords, session management)
10. Authorization Bypass (missing access controls)
11. CSRF (Cross-Site Request Forgery)
12. Session Fixation

### Input Validation (4 patterns)
13. XSS (Cross-Site Scripting) - reflected, stored, DOM-based
14. Path Traversal (file access)
15. File Upload Abuse (unrestricted uploads)
16. Integer Overflow/Underflow

### Cryptography (2 patterns)
17. Weak Cryptography (MD5, SHA1, weak keys)
18. Hardcoded Secrets (API keys, passwords in code)

### Python-Specific (2 patterns)
19. Pickle Deserialization (untrusted data)
20. eval/exec Execution (user input in eval)

---

## Configuration Example (.acrrc.yaml)

```yaml
# Project Configuration
project:
  name: "my-flask-app"
  root: "."
  
# Language Configuration
languages:
  python:
    enabled: true
    version: "3.10"
    
# Framework Configuration  
frameworks:
  flask:
    enabled: true
    
# Patterns Configuration
patterns:
  enabled:
    - sql-injection
    - xss
    - csrf
    - command-injection
    - auth-bypass
  severity_threshold: "medium"  # low, medium, high, critical
  
# LLM Configuration
llm:
  enabled: true
  provider: "anthropic"  # anthropic, openai
  model: "claude-3-5-sonnet-20241022"
  api_key_env: "ANTHROPIC_API_KEY"
  max_tokens: 4096
  cache_enabled: true
  
# Analysis Configuration
analysis:
  max_depth: 10
  timeout: 300  # seconds
  parallel: false  # Phase 5+
  
# Reporting Configuration
reporting:
  formats:
    - markdown
    - json
  output_dir: "./acr-reports"
  include_code_snippets: true
  max_snippet_lines: 10
  
# Exclusions
exclude:
  paths:
    - "tests/"
    - "venv/"
    - ".venv/"
    - "__pycache__/"
  files:
    - "*.pyc"
    - "*.pyo"
```

---

## Critical Implementation Notes

### 1. Error Handling Strategy
- **Parse Errors**: Gracefully handle malformed code, skip problematic files
- **Syntax Errors**: Report as info, don't fail the scan
- **AST Failures**: Fall back to regex-based pattern matching
- **Circular Dependencies**: Detect and break cycles in CFG/DFG
- **LLM Failures**: Cache fallback, continue with static analysis only

### 2. Sensitive Data Redaction (CRITICAL!)
**MUST redact BEFORE sending to LLM API**:
- API keys (regex: `[A-Za-z0-9]{32,}`)
- AWS credentials (regex: `AKIA[0-9A-Z]{16}`)
- Private keys (regex: `-----BEGIN.*PRIVATE KEY-----`)
- Passwords in strings (heuristic: `password.*=.*["'][^"']+["']`)
- Email addresses (optional, configurable)
- IP addresses (optional, configurable)

Implementation: `acr/llm/redaction.py`

### 3. LLM Cost Management
- **Cache aggressively**: Hash code snippet + prompt → cache result
- **Use cheaper models**: Claude Haiku for simple patterns, Sonnet for complex
- **Estimate costs**: Warn user before expensive scans
- **Local LLM support**: Phase 5+ (Ollama integration)

### 4. Performance Optimization
- **Incremental analysis**: Only analyze changed files (Phase 2+)
- **Parallel processing**: Analyze files in parallel (Phase 5+)
- **AST caching**: Cache parsed ASTs to disk
- **Pattern caching**: Compile patterns once, reuse across files

### 5. Testing Strategy
- **Baseline vulnerable apps**: Create 10 deliberately vulnerable Flask apps
- **Baseline secure apps**: Create 10 secure Flask apps (negative testing)
- **OWASP Benchmark**: Test against OWASP Benchmark for accuracy
- **Performance benchmarks**: Measure against 10k LOC Flask app

---

## What Previous Agents Found & Fixed

### Agent 0 (Planning)
- ✅ Created comprehensive PRD with 13 sections
- ✅ Created detailed TODO with 400+ tasks
- ✅ Designed phased approach (5 phases)
- ✅ Chose technology stack (Python, tree-sitter, networkx)

### Agent 1 (Review)
- ✅ Found timeline issues → Extended Phase 1 to 12-14 weeks
- ✅ Found feature contradictions → Clarified MVP scope
- ✅ Found missing error handling → Added comprehensive strategy
- ✅ Found missing false positive management → Added FP tracking system
- ✅ Found missing sensitive data redaction → Added redaction tasks

### Agent 2 (Second Review)
- ✅ Found missing real-world scenarios → Added monorepo, multi-language, legacy code handling
- ✅ Found missing Python edge cases → Added decorator, metaclass, async, generator patterns
- ✅ Found missing cloud/IaC security → Added AWS/Azure/GCP patterns
- ✅ Found LLM security issues → Added prompt injection protection, abuse prevention
- ✅ Found supply chain gaps → Added comprehensive dependency scanning

### Agent 3 (Final Review)
- ✅ Found missing legal/compliance → Added GDPR, licensing, ToS, vulnerability disclosure
- ✅ Found missing enterprise features → Added RBAC, SSO, audit logging, compliance reporting
- ✅ Found missing operations docs → Added monitoring, backup, update/rollback procedures
- ✅ Found missing documentation personas → Added developer, security engineer, DevOps, CTO guides

### Agent 4 (Polish)
- ✅ Verified legal/compliance completeness
- ✅ Verified enterprise features design
- ✅ Verified documentation strategy
- ✅ Standardized terminology (finding, attack pattern)
- ✅ Verified cross-references and phase numbering
- ✅ **Final confidence: 99%** → Ready for implementation

---

## Risks & Mitigations

### Risk 1: LLM API Costs
- **Risk**: Large codebases could be expensive
- **Mitigation**: Aggressive caching, cost estimation, cheaper models, local LLM option (Phase 5)

### Risk 2: High False Positive Rate
- **Risk**: Users overwhelmed by false alarms
- **Mitigation**: Target <15% FP rate, confidence scoring, user feedback loop, false positive management

### Risk 3: Analysis Speed
- **Risk**: Deep analysis could be slow
- **Mitigation**: Performance targets (1000 LOC/min), parallel processing (Phase 5), incremental analysis

### Risk 4: Market Acceptance
- **Risk**: Adversarial approach may not resonate
- **Mitigation**: Reduced MVP (12-14 weeks), early user feedback, clear value proposition

### Risk 5: Pattern Maintenance
- **Risk**: Patterns become outdated as frameworks evolve
- **Mitigation**: Pattern update mechanism (Phase 2), community contributions, auto-update (opt-in)

---

## Success Criteria for Phase 1 MVP

### Technical Success
- [ ] Can analyze 10k LOC Flask app in < 10 minutes
- [ ] Detects at least 80% of vulnerabilities in OWASP Benchmark
- [ ] False positive rate < 15%
- [ ] Generates readable Markdown and JSON reports
- [ ] CLI is intuitive and well-documented

### User Success
- [ ] Setup time < 5 minutes for new users
- [ ] First scan completes successfully in < 2 minutes
- [ ] Configuration is straightforward (.acrrc.yaml)
- [ ] Error messages are clear and actionable
- [ ] Documentation is comprehensive

### Business Success
- [ ] 100+ GitHub stars in first month
- [ ] 10+ community contributions (patterns, bug reports)
- [ ] Positive feedback from 5+ beta users
- [ ] Featured on security community forums (Reddit, HN, etc.)

---

## What to Build First (Week 1-2)

### Day 1-2: Project Setup
1. Initialize Poetry project (`poetry init`)
2. Create LICENSE file (MIT recommended)
3. Create README.md with project overview
4. Set up .gitignore
5. Create CONTRIBUTING.md
6. Create SECURITY.md (vulnerability disclosure policy)
7. Set up pre-commit hooks (black, ruff, mypy)

### Day 3-5: Configuration System
1. Design .acrrc.yaml schema
2. Implement config loader (`acr/config/loader.py`)
3. Implement config validator (`acr/config/validator.py`)
4. Create Pydantic models for config (`acr/models/config.py`)
5. Write unit tests for config system
6. Create .acrrc.yaml.example

### Day 6-8: CLI Framework
1. Set up Click CLI framework (`acr/cli/`)
2. Implement `acr init` command (generates .acrrc.yaml)
3. Implement `acr config validate` command
4. Implement `acr version` command
5. Add shell autocompletion (bash, zsh, fish)
6. Write tests for CLI commands

### Day 9-10: Logging & Error Handling
1. Set up logging infrastructure (`acr/utils/logger.py`)
2. Define custom exceptions (`acr/utils/errors.py`)
3. Implement error handling strategy
4. Add debug mode (--verbose flag)
5. Write tests for error handling

### Day 11-14: Data Models
1. Define Finding model (`acr/models/finding.py`)
2. Define Pattern model (`acr/models/pattern.py`)
3. Define Vulnerability model
4. Add serialization/deserialization
5. Write tests for data models

---

## Questions for Clarification (If Needed)

Before starting implementation, consider these questions:

1. **License Choice**: MIT or Apache 2.0? (Recommendation: MIT for simplicity)
2. **Privacy Policy**: Where to host? (Recommendation: docs/PRIVACY.md)
3. **LLM Provider**: Primary Claude or OpenAI? (Recommendation: Claude 3.5 Sonnet)
4. **API Key Storage**: Environment variable or config file? (Recommendation: Env var for security)
5. **Report Storage**: Default location? (Recommendation: ./acr-reports/)
6. **Vulnerability Disclosure**: Email address? (Recommendation: security@[domain])

---

## Ready to Start?

You have everything you need to begin scaffolding and building ACR Phase 1:

1. ✅ Comprehensive PRD (PRD.md)
2. ✅ Detailed TODO (TODO.md)
3. ✅ Technical architecture
4. ✅ File structure
5. ✅ Dependencies list
6. ✅ Phase 1 priorities
7. ✅ Performance targets
8. ✅ Success criteria
9. ✅ Risk mitigations
10. ✅ 99% confidence from review process

**Next Steps**:
1. Complete Week 0 legal tasks (LICENSE, PRIVACY, SECURITY)
2. Set up project scaffolding (Week 1)
3. Begin Phase 1 implementation (Weeks 1-14)

**Good luck! The foundation is solid. Time to build.** 🚀

---

## Quick Reference Links

- **Full PRD**: See PRD.md
- **Full TODO**: See TODO.md
- **Agent Decisions**: See AGENT0-4_JOURNAL.md
- **Original Idea**: See IDEA.md

**Questions?** Review the agent journals for detailed rationale on any decision.
