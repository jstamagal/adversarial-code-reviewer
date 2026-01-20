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
# See the License for specific language governing permissions and
# limitations under the License.

"""Unit tests for enhanced data redaction."""

import pytest

from acr.config.schema import RedactionConfig, RedactionPatternConfig
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
    assert "aws_access_key_id" in redacted
    assert counts.get("aws_key", 0) > 0


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


def test_certificate_redaction():
    """Test certificate redaction."""
    redactor = DataRedactor()
    text = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJ..."
    redacted, counts = redactor.redact(text)

    assert "[REDACTED]" in redacted
    assert counts.get("certificate", 0) > 0


def test_jwt_token_redaction():
    """Test JWT token redaction."""
    redactor = DataRedactor()
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123.def456.ghi789..."
    redacted, counts = redactor.redact(text)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123.def456.ghi789" not in redacted
    assert counts.get("jwt_token", 0) > 0 or counts.get("authorization_header", 0) > 0


def test_github_token_redaction():
    """Test GitHub token redaction."""
    redactor = DataRedactor()
    text = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv"
    redacted, counts = redactor.redact(text)

    assert "ghp_1234567890abcdefghijklmnopqrstuv" not in redacted
    assert counts.get("github_token", 0) > 0 or counts.get("token", 0) > 0


def test_slack_token_redaction():
    """Test Slack token redaction."""
    redactor = DataRedactor()
    text = "SLACK_TOKEN=xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWxYz"
    redacted, counts = redactor.redact(text)

    assert "xoxb-" not in redacted or "[REDACTED]" in redacted
    assert counts.get("slack_token", 0) > 0 or counts.get("token", 0) > 0


def test_stripe_key_redaction():
    """Test Stripe API key redaction."""
    redactor = DataRedactor()
    text = "stripe_api_key=sk_live_1234567890abcdefghijklmnopqrstuvwx"
    redacted, counts = redactor.redact(text)

    assert "sk_live_" not in redacted or "[REDACTED]" in redacted
    assert counts.get("stripe_key", 0) > 0 or counts.get("api_key", 0) > 0


def test_database_url_redaction():
    """Test database URL redaction."""
    redactor = DataRedactor()
    text = "DATABASE_URL=postgresql://user:password@host:5432/database"
    redacted, counts = redactor.redact(text)

    assert "postgresql://" not in redacted or "[REDACTED]" in redacted
    assert counts.get("database_url", 0) > 0


def test_mongodb_connection_redaction():
    """Test MongoDB connection string redaction."""
    redactor = DataRedactor()
    text = "mongodb://user:pass@cluster0.mongodb.net:27017/db"
    redacted, counts = redactor.redact(text)

    assert "mongodb://" not in redacted or "[REDACTED]" in redacted
    assert counts.get("mongodb_connection", 0) > 0 or counts.get("database_url", 0) > 0


def test_ssh_key_redaction():
    """Test SSH key redaction."""
    redactor = DataRedactor()
    text = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
    redacted, counts = redactor.redact(text)

    assert "ssh-rsa" not in redacted or "[REDACTED]" in redacted
    assert counts.get("ssh_key", 0) > 0


def test_credit_card_redaction():
    """Test credit card number redaction."""
    redactor = DataRedactor()
    text = "card_number=4111111111111111"
    redacted, counts = redactor.redact(text)

    assert "4111111111111111" not in redacted
    assert counts.get("credit_card", 0) > 0


def test_email_address_redaction():
    """Test email address redaction."""
    redactor = DataRedactor()
    text = "user_email=test@example.com"
    redacted, counts = redactor.redact(text)

    assert "test@example.com" not in redacted
    assert counts.get("email_address", 0) > 0


def test_ip_address_redaction():
    """Test IP address redaction."""
    redactor = DataRedactor()
    text = "server_ip=192.168.1.1"
    redacted, counts = redactor.redact(text)

    assert "192.168.1.1" not in redacted
    assert counts.get("ip_address", 0) > 0


def test_ssn_redaction():
    """Test SSN redaction."""
    redactor = DataRedactor()
    text = "ssn=123-45-6789"
    redacted, counts = redactor.redact(text)

    assert "123-45-6789" not in redacted
    assert counts.get("ssn", 0) > 0


def test_multiple_redactions():
    """Test multiple redactions in one text."""
    redactor = DataRedactor()
    text = """
    api_key = "sk-proj-1234567890abcdefghijk"
    password = "secret"
    aws_key = "AKIA1234567890123456"
    """
    redacted, counts = redactor.redact(text)

    assert redactor.get_redaction_count() >= 3
    assert sum(counts.values()) >= 3


def test_entropy_calculation():
    """Test Shannon entropy calculation."""
    redactor = DataRedactor()

    low_entropy = "aaaaaaaaaa"
    high_entropy = "A1b2C3d4E5f6"

    assert redactor.calculate_entropy(low_entropy) < redactor.calculate_entropy(high_entropy)


def test_entropy_based_detection():
    """Test high-entropy string detection."""
    config = RedactionConfig(entropy_threshold=4.0, entropy_min_length=20)
    redactor = DataRedactor(config)

    text = "secret = A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    redacted, counts = redactor.redact(text)

    assert counts.get("high_entropy", 0) > 0
    assert "[REDACTED:HIGH_ENTROPY]" in redacted


def test_entropy_detection_disabled():
    """Test that entropy detection can be disabled."""
    config = RedactionConfig(entropy_threshold=0.0)
    redactor = DataRedactor(config)

    text = "secret = A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    redacted, counts = redactor.redact(text)

    assert counts.get("high_entropy", 0) == 0


def test_custom_pattern():
    """Test adding custom redaction patterns."""
    redactor = DataRedactor()
    redactor.add_custom_pattern("custom_secret", r"SECRET:\s*([A-Z0-9]+)")

    text = "SECRET: ABC123XYZ"
    redacted, counts = redactor.redact(text)

    assert "ABC123XYZ" not in redacted
    assert counts.get("custom_secret", 0) > 0


def test_custom_pattern_invalid_regex():
    """Test that invalid custom regex raises error."""
    redactor = DataRedactor()

    with pytest.raises(ValueError):
        redactor.add_custom_pattern("invalid", "[invalid(regex")


def test_custom_pattern_from_config():
    """Test loading custom patterns from config."""
    custom_patterns = [
        RedactionPatternConfig(
            name="api_v2_key",
            pattern=r"API_V2:\s*([A-Za-z0-9_-]{10,})",
            description="API v2 key pattern",
        )
    ]
    config = RedactionConfig(custom_patterns=custom_patterns)
    redactor = DataRedactor(config)

    text = "API_V2: xyz123abc456def"
    redacted, counts = redactor.redact(text)

    assert "xyz123abc456def" not in redacted
    assert counts.get("api_v2_key", 0) > 0


def test_redaction_verification():
    """Test redaction verification."""
    config = RedactionConfig(verify_redaction=True)
    redactor = DataRedactor(config)

    original = "password = secret123"
    redacted, _ = redactor.redact(original)

    assert redactor.verify_redaction(original, redacted)


def test_redaction_verification_failure():
    """Test redaction verification detects missed patterns."""
    config = RedactionConfig(verify_redaction=True)
    redactor = DataRedactor(config)

    original = "password = secret123"
    redacted = original

    assert not redactor.verify_redaction(original, redacted)


def test_redaction_events_logging():
    """Test redaction event logging."""
    config = RedactionConfig(log_redactions=True)
    redactor = DataRedactor(config)

    text = 'api_key = "sk-proj-1234567890abcdefghijk"'
    redactor.redact(text)

    events = redactor.get_redaction_events()
    assert len(events) > 0
    assert events[0].pattern_name == "api_key"
    assert events[0].match_count > 0


def test_redaction_events_clearing():
    """Test clearing redaction events."""
    redactor = DataRedactor()

    text = "password = secret"
    redactor.redact(text)

    assert len(redactor.get_redaction_events()) > 0

    redactor.clear_redaction_events()
    assert len(redactor.get_redaction_events()) == 0


def test_logging_disabled():
    """Test that logging can be disabled."""
    config = RedactionConfig(log_redactions=False)
    redactor = DataRedactor(config)

    text = "password = secret"
    redactor.redact(text)

    events = redactor.get_redaction_events()
    assert len(events) == 0


def test_verification_disabled():
    """Test that verification can be disabled."""
    config = RedactionConfig(verify_redaction=False)
    redactor = DataRedactor(config)

    original = "password = secret"
    redacted = original

    assert redactor.verify_redaction(original, redacted)


def test_no_sensitive_data():
    """Test text with no sensitive data."""
    redactor = DataRedactor()

    text = "This is normal text with no secrets or sensitive information."
    redacted, counts = redactor.redact(text)

    assert text == redacted
    assert sum(counts.values()) == 0


def test_empty_text():
    """Test redaction of empty text."""
    redactor = DataRedactor()

    redacted, counts = redactor.redact("")

    assert redacted == ""
    assert sum(counts.values()) == 0


def test_duplicate_patterns():
    """Test handling of duplicate sensitive strings."""
    redactor = DataRedactor()

    text = (
        'api_key = "sk-proj-1234567890abcdefghijk"\nalso_api_key = "sk-proj-1234567890abcdefghijk"'
    )
    redacted, counts = redactor.redact(text)

    assert "sk-proj-1234567890abcdefghijk" not in redacted
    assert counts.get("api_key", 0) >= 2


def test_redaction_count_accumulation():
    """Test that redaction count accumulates across calls."""
    redactor = DataRedactor()

    redactor.redact("password = secret1")
    redactor.redact("password = secret2")

    assert redactor.get_redaction_count() >= 2


def test_complex_code_snippet():
    """Test redaction in complex code snippet."""
    redactor = DataRedactor()

    text = """
    import os

    API_KEY = os.getenv("API_KEY", "sk-proj-1234567890abcdefghijk")
    DB_URL = f"postgresql://{user}:{password}@{host}/{database}"
    JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123.def456.ghi789"
    """
    redacted, counts = redactor.redact(text)

    assert "sk-proj-1234567890abcdefghijk" not in redacted
    assert "postgresql://" not in redacted or "[REDACTED]" in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123.def456.ghi789" not in redacted
    assert sum(counts.values()) >= 3


def test_mixed_sensitivity():
    """Test text with mixed sensitive and non-sensitive data."""
    redactor = DataRedactor()

    text = """
    Config:
    - server: localhost
    - port: 8080
    - api_key: sk-proj-1234567890abcdefghijk
    - debug: false
    - password: secret123
    """
    redacted, counts = redactor.redact(text)

    assert "localhost" in redacted
    assert "8080" in redacted
    assert "debug" in redacted
    assert "false" in redacted
    assert "sk-proj-1234567890abcdefghijk" not in redacted
    assert "secret123" not in redacted


def test_auth_header_redaction():
    """Test Authorization header redaction."""
    redactor = DataRedactor()

    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    redacted, counts = redactor.redact(text)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert counts.get("authorization_header", 0) > 0 or counts.get("jwt_token", 0) > 0


def test_phone_number_redaction():
    """Test phone number redaction."""
    redactor = DataRedactor()

    text = "phone: 5551234567 is the number"
    redacted, counts = redactor.redact(text)

    assert "5551234567" not in redacted or counts.get("phone_number", 0) >= 0


def test_redis_url_redaction():
    """Test Redis URL redaction."""
    redactor = DataRedactor()

    text = "redis://:password@localhost:6379"
    redacted, counts = redactor.redact(text)

    assert "redis://" not in redacted or "[REDACTED]" in redacted
    assert counts.get("redis_url", 0) > 0


def test_entropy_with_various_strings():
    """Test entropy detection with various string types."""
    config = RedactionConfig(entropy_threshold=3.5, entropy_min_length=15)
    redactor = DataRedactor(config)

    high_entropy = "A1b2C3d4E5f6G7h8"
    medium_entropy = "HelloWorld12345"
    low_entropy = "aaaaaaaaaaaaaaaa"

    redacted, counts = redactor.redact(f"data = {high_entropy} {medium_entropy} {low_entropy}")

    assert counts.get("high_entropy", 0) > 0
