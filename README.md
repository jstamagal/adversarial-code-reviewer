# Adversarial Code Reviewer (ACR)

An AI-powered security tool that flips the code review paradigm by providing adversarial analysis instead of helpful suggestions. Think of it as an AI red-teamer for your codebase.

## What is ACR?

Traditional code review: "Here's what you could improve"  
Adversarial code review: "Here's how I can exploit your code"

ACR forces defensive thinking during development by:
- Finding unintended behaviors through adversarial testing
- Breaking edge cases systematically
- Abusing features in unanticipated ways
- Understanding and subverting business logic
- Generating property-based tests that stress-test assumptions

## Features

- **Multi-Language Support**: Python (MVP), JavaScript/TypeScript, Java/Kotlin, Go, Rust
- **Static Analysis**: AST, Control Flow Graphs (CFG), Data Flow Graphs (DFG)
- **Taint Tracking**: Identify security-sensitive data flows
- **Attack Pattern Library**: 20+ core attack patterns (SQL injection, XSS, CSRF, etc.)
- **LLM-Powered Intelligence**: Claude/GPT-4 for complex attack scenarios
- **Multiple Report Formats**: Markdown, JSON, SARIF, HTML, YAML
- **CI/CD Integration**: GitHub Actions, GitLab CI, CircleCI, Jenkins

## Installation

```bash
pip install adversarial-code-reviewer
```

## Quick Start

```bash
# Initialize configuration
acr init

# Scan your codebase
acr scan .

# Generate a report
acr report --format markdown
```

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [CLI Reference](docs/cli-reference.md)
- [Configuration Guide](docs/configuration.md)
- [Pattern Reference](docs/pattern-reference.md)
- [Architecture](docs/architecture.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security

For security considerations and vulnerability disclosure, see [SECURITY.md](SECURITY.md).

## Disclaimer

ACR is designed for defensive security and educational purposes. Users must not use ACR to attack systems without authorization. Users are responsible for how they use generated attack scenarios.
