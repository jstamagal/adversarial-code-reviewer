"""Setup script for Adversarial Code Reviewer."""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="adversarial-code-reviewer",
    version="0.1.0",
    author="ACR Contributors",
    author_email="contact@adversarial-code-reviewer.com",
    description="AI-powered adversarial code reviewer - thinks like an attacker to find vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/adversarial-code-reviewer/acr",
    project_urls={
        "Bug Tracker": "https://github.com/adversarial-code-reviewer/acr/issues",
        "Documentation": "https://adversarial-code-reviewer.readthedocs.io",
        "Source Code": "https://github.com/adversarial-code-reviewer/acr",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0.0",
        "networkx>=3.0.0",
        "anthropic>=0.21.0",
        "openai>=1.0.0",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
        "tree-sitter>=0.20.0",
        "tree-sitter-languages>=1.8.0",
        "diskcache>=5.6.0",
        "keyring>=24.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=4.1.0",
            "black>=24.0.0",
            "ruff>=0.2.0",
            "mypy>=1.8.0",
            "pre-commit>=3.6.0",
            "pytest-asyncio>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "acr=acr.__main__:cli",
        ],
    },
    include_package_data=True,
    keywords=[
        "security",
        "static-analysis",
        "vulnerability-scanner",
        "code-review",
        "red-team",
        "pentesting",
        "ast",
        "code-analysis",
    ],
)
