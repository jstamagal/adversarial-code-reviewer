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

"""Unit tests for attack generator."""

import pytest
from unittest.mock import MagicMock, patch
from acr.llm.attack_generator import AttackGenerator


def test_attack_generator_initialization():
    """Test AttackGenerator initialization."""
    with patch("acr.llm.attack_generator.create_client") as mock_create:
        mock_client = MagicMock()
        mock_create.return_value = mock_client

        generator = AttackGenerator()

        assert generator.client == mock_client
        assert generator._call_count == 0
        assert generator._max_calls_per_scan == 100
        mock_create.assert_called_once()


def test_attack_generator_with_custom_client():
    """Test AttackGenerator with custom client."""
    mock_client = MagicMock()

    generator = AttackGenerator(llm_client=mock_client)

    assert generator.client == mock_client


def test_attack_generator_call_limit():
    """Test that call limit is enforced."""
    mock_client = MagicMock()

    generator = AttackGenerator(llm_client=mock_client)
    generator._call_count = 100

    with pytest.raises(RuntimeError, match="LLM call limit .* exceeded"):
        generator.generate_attack_vector("code", "pattern")


def test_generate_attack_vector():
    """Test attack vector generation."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Attack vector response"

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_attack_vector(
        code="user_input = request.form.get('user')",
        pattern="SQL Injection",
        context={"file": "app.py", "line": 42},
    )

    assert result == "Attack vector response"
    assert generator._call_count == 1
    mock_client.generate.assert_called_once()


def test_explain_vulnerability():
    """Test vulnerability explanation generation."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Vulnerability explanation"

    generator = AttackGenerator(llm_client=mock_client)
    finding = {
        "severity": "high",
        "pattern": "SQL Injection",
        "file": "app.py",
        "line": 42,
    }
    result = generator.explain_vulnerability(
        code="query = f\"SELECT * FROM users WHERE id='{id}'\"",
        finding=finding,
    )

    assert result == "Vulnerability explanation"
    assert generator._call_count == 1


def test_suggest_remediation():
    """Test remediation suggestion generation."""
    mock_client = MagicMock()
    mock_client.generate.return_value = """Vulnerability: SQL Injection
Remediation Code:
```python
query = "SELECT * FROM users WHERE id=%s"
cursor.execute(query, (id,))
```
Explanation: Uses parameterized queries to prevent injection"""

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.suggest_remediation(
        code="query = f\"SELECT * FROM users WHERE id='{id}'\"",
        pattern="SQL Injection",
    )

    assert result["description"] is not None
    assert "Vulnerability: SQL Injection" in result["description"]
    assert 'query = "SELECT * FROM users WHERE id=%s"' not in result.get("code_before", "")
    assert "cursor.execute(query, (id,))" not in result.get("code_after", "")


def test_suggest_remediation_with_language():
    """Test remediation with different language."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Remediation code"

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.suggest_remediation(
        code="const query = `SELECT * FROM users`",
        pattern="SQL Injection",
        language="javascript",
    )

    assert result["description"] == "Remediation code"


def test_generate_business_logic_abuse():
    """Test business logic abuse generation."""
    mock_client = MagicMock()
    mock_client.generate.return_value = """- User can add items to cart but never checkout to reserve inventory
- Coupon codes can be stacked without limit
- Price manipulation through quantity discounts"""

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_business_logic_abuse(
        code="def add_to_cart(item, quantity): ...",
        context={"endpoint": "/api/cart/add"},
    )

    assert len(result) == 3
    assert "User can add items to cart" in result[0]


def test_generate_business_logic_abuse_with_rules():
    """Test business logic abuse with custom rules."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "- Abuse scenario"

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_business_logic_abuse(
        code="def checkout(cart): ...",
        context={"endpoint": "/api/checkout"},
        business_rules=["Coupon limit: 1 per order", "Inventory must be reserved"],
    )

    assert len(result) == 1
    assert "Abuse scenario" in result[0]


def test_parse_scenarios():
    """Test scenario parsing from LLM response."""
    mock_client = MagicMock()
    mock_client.generate.return_value = """Scenario 1
- First abuse case
- Second abuse case
Third scenario
* Fourth scenario"""

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_business_logic_abuse("code", {})

    assert len(result) == 4


def test_parse_scenarios_limit_to_5():
    """Test that scenarios are limited to 5."""
    mock_client = MagicMock()
    scenarios_list = [f"- Scenario {i}" for i in range(10)]
    mock_client.generate.return_value = "\n".join(scenarios_list)

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_business_logic_abuse("code", {})

    assert len(result) == 5


def test_generate_complete_finding():
    """Test complete finding generation."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Response"

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_complete_finding(
        code="query = f\"SELECT * FROM users WHERE id='{id}'\"",
        file_path="app.py",
        line_number=42,
        pattern="SQL Injection",
        severity="high",
        category="injection",
    )

    assert result.id is not None
    assert result.severity == "high"
    assert result.title == "SQL Injection in app.py:42"
    assert result.category == "injection"
    assert result.confidence == "medium"
    assert result.location.file == "app.py"
    assert result.location.line == 42
    assert result.impact.confidentiality == "high"


def test_generate_complete_finding_with_context():
    """Test complete finding with context."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Response"

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.generate_complete_finding(
        code="code",
        file_path="app.py",
        line_number=42,
        pattern="XSS",
        severity="critical",
        category="xss",
        context={"function": "render_user_input", "class": "UserView"},
    )

    assert result.location.file == "app.py"
    assert result.location.line == 42


def test_map_severity_to_impact():
    """Test severity to impact mapping."""
    generator = AttackGenerator(llm_client=MagicMock())

    assert generator._map_severity_to_impact("critical") == "critical"
    assert generator._map_severity_to_impact("high") == "high"
    assert generator._map_severity_to_impact("medium") == "medium"
    assert generator._map_severity_to_impact("low") == "low"
    assert generator._map_severity_to_impact("info") == "none"
    assert generator._map_severity_to_impact("unknown") == "medium"


def test_get_call_count():
    """Test getting call count."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Response"

    generator = AttackGenerator(llm_client=mock_client)
    assert generator.get_call_count() == 0

    generator.generate_attack_vector("code", "pattern")
    assert generator.get_call_count() == 1

    generator.explain_vulnerability("code", {})
    assert generator.get_call_count() == 2


def test_reset_call_count():
    """Test resetting call count."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Response"

    generator = AttackGenerator(llm_client=mock_client)
    generator.generate_attack_vector("code", "pattern")
    assert generator.get_call_count() == 1

    generator.reset_call_count()
    assert generator.get_call_count() == 0


def test_set_max_calls():
    """Test setting max calls."""
    generator = AttackGenerator(llm_client=MagicMock())
    assert generator._max_calls_per_scan == 100

    generator.set_max_calls(50)
    assert generator._max_calls_per_scan == 50


def test_sensitive_data_redaction():
    """Test that sensitive data is redacted before LLM calls."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Response"

    generator = AttackGenerator(llm_client=mock_client)

    code_with_secret = """
    api_key = "sk-1234567890abcdef"
    password = "super_secret_password"
    """

    generator.generate_attack_vector(
        code=code_with_secret,
        pattern="Hardcoded Secrets",
    )

    assert mock_client.generate.called
    assert generator.redactor.get_redaction_count() > 0


def test_parse_remediation_with_before_after():
    """Test remediation parsing with before/after code."""
    mock_client = MagicMock()
    mock_client.generate.return_value = """before: query = "SELECT * FROM users WHERE id='" + id + "'"
after: query = "SELECT * FROM users WHERE id=%s"
cursor.execute(query, (id,))"""

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.suggest_remediation("code", "pattern")

    assert result["code_before"] is not None
    assert result["code_after"] is not None


def test_parse_remediation_no_code_blocks():
    """Test remediation parsing without explicit code blocks."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Use parameterized queries instead of string concatenation"

    generator = AttackGenerator(llm_client=mock_client)
    result = generator.suggest_remediation("code", "pattern")

    assert result["description"] == "Use parameterized queries instead of string concatenation"
    assert result.get("code_before") is None
    assert result.get("code_after") is None


def test_multiple_calls_increment():
    """Test that multiple calls increment counter."""
    mock_client = MagicMock()
    mock_client.generate.return_value = "Response"

    generator = AttackGenerator(llm_client=mock_client)

    generator.generate_attack_vector("code1", "pattern1")
    generator.explain_vulnerability("code2", {})
    generator.suggest_remediation("code3", "pattern3")
    generator.generate_business_logic_abuse("code4", {})

    assert generator.get_call_count() == 4
