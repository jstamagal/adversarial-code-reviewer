# Installation Guide

This guide will help you install and set up the
Adversarial Code Reviewer (ACR) on your system.

## Table of Contents

- [System Requirements](#system-requirements)
- [Python Requirements](#python-requirements)
- [Installation Methods](#installation-methods)
  - [Method 1: Install via pip (Recommended)](#method-1-install-via-pip-recommended)
  - [Method 2: Install via Poetry](#method-2-install-via-poetry)
  - [Method 3: Install from Source](#method-3-install-from-source)
- [Installation Verification](#installation-verification)
- [Configuration Setup](#configuration-setup)
- [LLM Configuration](#llm-configuration)
- [Platform-Specific Notes](#platform-specific-notes)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)
- [Upgrading](#upgrading)

## System Requirements

Before installing ACR, ensure your system meets the following requirements:

- **Operating System**: Linux, macOS, or Windows
- **Disk Space**: 100 MB for installation (additional space for cache)
- **Memory**: 2 GB RAM minimum, 4 GB recommended
- **Internet Connection**: Required for LLM API calls (optional for local-only analysis)

## Python Requirements

ACR requires Python 3.8 or later. Check your Python version:

```bash
python --version
# or
python3 --version
```

If you need to install Python:

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install python3.11 python3.11-venv python3-pip
```

### macOS

```bash
brew install python@3.11
```

### Windows

Download and install Python from [python.org](https://www.python.org/downloads/)

## Installation Methods

### Method 1: Install via pip (Recommended)

This is the simplest method for most users.

```bash
pip install adversarial-code-reviewer
```

If you don't have permission to install globally, use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install adversarial-code-reviewer
```

#### Using Bun (for package management)

If you prefer using Bun for package management:

```bash
bun install -g adversarial-code-reviewer
```

Or in a Bun project:

```bash
bun add adversarial-code-reviewer
```

### Method 2: Install via Poetry

Poetry is recommended for development or if you want better dependency management.

1. Install Poetry (if not already installed):

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

2. Install ACR:

```bash
poetry install
```

3. Use ACR via Poetry:

```bash
poetry run acr --version
```

Or activate the virtual environment:

```bash
poetry shell
acr --version
```

### Method 3: Install from Source

This method is recommended if you want to contribute or need the latest development version.

1. Clone the repository:

```bash
git clone https://github.com/adversarial-code-reviewer/acr.git
cd acr
```

2. Install in development mode:

```bash
pip install -e .
```

Or using Poetry:

```bash
poetry install
```

3. Verify installation:

```bash
acr --version
```

## Installation Verification

After installation, verify that ACR is working correctly:

```bash
# Check version
acr --version

# Run diagnostics
acr doctor

# Show help
acr --help
```

Expected output from `acr --version`:

```text
ACR (Adversarial Code Reviewer) version 0.1.0
Python 3.11.0
```

Expected output from `acr doctor` should show green checkmarks for all checks.

## Configuration Setup

After installing ACR, initialize the configuration file:

```bash
acr init
```

This creates a `.acrrc.yaml` file in your current directory with default settings:

```yaml
# Language-specific settings
languages:
  python:
    version: "3.8+"
    framework: ["flask", "django", "fastapi"]

# Attack pattern settings
patterns:
  enabled: ["injection", "auth", "xss", "business-logic"]
  severity_threshold: "medium"
  custom_patterns: "./patterns/"

# Analysis settings
analysis:
  max_recursion_depth: 10
  enable_data_flow_analysis: true
  enable_control_flow_analysis: true
  enable_stateful_analysis: true

# Reporting settings
reporting:
  format: ["markdown", "json"]
  output_dir: "./reports/"
  include_code_snippets: true
  include_fix_suggestions: true
```

You can customize this file to suit your needs. See the [Configuration Guide](docs/configuration.md) for all available options.

## LLM Configuration

ACR can use LLMs (OpenAI GPT-4 or Anthropic Claude) for intelligent attack generation. This is optional but recommended for better results.

### OpenAI Configuration

1. Get an API key from [OpenAI](https://platform.openai.com/api-keys)
2. Set the API key as an environment variable:

```bash
export OPENAI_API_KEY="your-api-key-here"
```

Or use keyring for secure storage:

```bash
acr config set llm.provider openai
acr config set llm.api_key your-api-key-here
```

### Anthropic Claude Configuration

1. Get an API key from [Anthropic](https://console.anthropic.com/)
2. Set the API key as an environment variable:

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

Or use keyring:

```bash
acr config set llm.provider anthropic
acr config set llm.api_key your-api-key-here
```

### Configuration File

Add LLM settings to your `.acrrc.yaml`:

```yaml
llm:
  provider: "anthropic"  # or "openai"
  model: "claude-3-5-sonnet-20241022"
  max_calls_per_scan: 10
  timeout: 30
```

**Note**: LLM API calls are optional. ACR will still work with static analysis only if you don't configure an LLM provider.

## Platform-Specific Notes

### Linux

#### Ubuntu/Debian Dependencies

Some dependencies may require system packages:

```bash
sudo apt-get update
sudo apt-get install python3-dev build-essential
```

#### CentOS/RHEL

```bash
sudo yum install python3-devel gcc make
```

#### Arch Linux

```bash
sudo pacman -S python python-pip
```

### macOS

#### Homebrew

```bash
brew install python@3.11
```

#### Xcode Command Line Tools

Some compilation may require Xcode tools:

```bash
xcode-select --install
```

### Windows

#### Python Installation

1. Download Python from [python.org](https://www.python.org/downloads/)
2. During installation, check "Add Python to PATH"
3. Open Command Prompt or PowerShell

#### Visual C++ Build Tools

Some packages may require build tools:

1. Download [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
2. Install "Desktop development with C++" workload

#### Git Bash

For better compatibility, consider using [Git for Windows](https://git-scm.com/download/win) which includes Git Bash.

## Troubleshooting

### Issue: `pip: command not found`

**Solution**: Install pip:

```bash
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

Or on Ubuntu/Debian:

```bash
sudo apt-get install python3-pip
```

### Issue: `Permission denied` during installation

**Solution**: Use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install adversarial-code-reviewer
```

Or use `--user` flag:

```bash
pip install --user adversarial-code-reviewer
```

### Issue: `tree_sitter` import error

**Solution**: Reinstall tree-sitter:

```bash
pip uninstall tree-sitter tree-sitter-languages
pip install tree-sitter tree-sitter-languages
```

### Issue: LLM API connection timeout

**Solution**: Check your internet connection and API key:

```bash
acr doctor
```

Verify API key is set:

```bash
echo $OPENAI_API_KEY  # or $ANTHROPIC_API_KEY
```

### Issue: ModuleNotFoundError

**Solution**: Ensure ACR is installed correctly:

```bash
pip show adversarial-code-reviewer
```

If not found, reinstall:

```bash
pip install --force-reinstall adversarial-code-reviewer
```

### Issue: Python version too old

**Error message**: `Python 3.8+ required, but you have 3.7`

**Solution**: Upgrade Python using your package manager or install from python.org.

### Issue: Virtual environment activation fails on Windows

**Error message**: `'venv\Scripts\activate' is not recognized`

**Solution**: Use PowerShell and run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1
```

Or use Command Prompt:

```cmd
venv\Scripts\activate.bat
```

### Issue: `acr doctor` shows failures

**Solution**: Check each failure:

- **Python version**: Upgrade to 3.8+
- **Dependencies**: `pip install --upgrade [package]`
- **Tree-sitter**: Reinstall tree-sitter and tree-sitter-languages
- **Configuration**: Run `acr init` to create config

### Issue: Slow installation on Windows

**Solution**: Use a virtual environment and disable antivirus temporarily:

```bash
python -m venv venv
venv\Scripts\activate
pip install adversarial-code-reviewer --no-cache-dir
```

### Getting Help

If you encounter issues not covered here:

1. Run `acr doctor` for diagnostics
2. Run with `--verbose` flag for more details: `acr --verbose scan .`
3. Check existing [GitHub Issues](https://github.com/adversarial-code-reviewer/acr/issues)
4. Create a new issue with:
   - Your OS and version
   - Python version
   - Error message
   - Steps to reproduce
   - Output of `acr doctor`

## Uninstallation

To uninstall ACR:

```bash
pip uninstall adversarial-code-reviewer
```

Or with Poetry:

```bash
poetry remove adversarial-code-reviewer
```

**Note**: This does not remove:

- Configuration files (`.acrrc.yaml`, `.acr-ignore`, `.acr-state`)
- Cached analysis results
- Custom patterns

To remove configuration:

```bash
rm -f .acrrc.yaml .acr-ignore .acr-state
rm -rf .acr-cache/
```

## Upgrading

To upgrade to the latest version:

```bash
pip install --upgrade adversarial-code-reviewer
```

Or with Poetry:

```bash
poetry update
```

To check your current version:

```bash
acr --version
```

To check for updates (if available):

```bash
acr check-update
```

**Note**: After upgrading, review the [CHANGELOG](CHANGELOG.md) for breaking changes or new features.

## Next Steps

After installation, you're ready to use ACR!

- **Quick Start**: See [Quick Start Tutorial](docs/quick-start.md)
- **CLI Reference**: See [CLI Reference](docs/cli-reference.md)
- **Configuration**: See [Configuration Guide](docs/configuration.md)
- **Patterns**: See [Pattern Reference](docs/pattern-reference.md)

Run your first scan:

```bash
acr init
acr scan .
```
