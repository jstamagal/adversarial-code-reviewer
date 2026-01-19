# Copyright 2026 Adversarial Code Reviewer Contributors
#
# Licensed under the MIT License;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for data redaction."""

import pytest
from acr.llm.redaction import DataRedactor


def test_api_key_redaction():
    """Test API key redaction."""
    redactor = DataRedactor()
    text = 'api_key = "sk-proj-1234567890abcdefghijk"'
    redacted, counts = redactor.redact(text)

    assert "sk-proj-1234567890abcdefghijk" not in redacted
    assert "[REDACTED]" in redacted
    assert counts.get("api_key", 0) > 0


def test_aws_key_redaction():
    """Test AWS access key redaction."""
    redactor = DataRedactor()
    text = "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'"
    redacted, counts = redactor.redact(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED]" in redacted
    assert "aws_access_key_id" in redacted  # Variable name should be preserved


def test_password_redaction():
    """Test password redaction."""
    redactor = DataRedactor()
    text = "password = 'secret123'"
    redacted, counts = redactor.redact(text)

    assert "secret123" not in redacted
    assert "[REDACTED]" in redacted
    assert counts.get("password", 0) > 0


def test_private_key_redaction():
    """Test private key redaction."""
    redactor = DataRedactor()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    redacted, counts = redactor.redact(text)

    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted or "[REDACTED]" in redacted
    assert counts.get("private_key", 0) > 0


def test_multiple_redactions():
    """Test multiple redactions in one text."""
    redactor = DataRedactor()
    text = """
    api_key = "sk-12345"
    password = "secret"
    aws_key = "AKIA1234567890123456"
    """
    redacted, counts = redactor.redact(text)

    assert redactor.get_redaction_count() >= 2
    assert sum(counts.values()) >= 2
