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

"""Tests for prompt templates."""


from acr.llm.prompts import PromptTemplates


class TestPromptTemplates:
    """Tests for prompt template generation."""

    def test_generate_attack_vector_basic(self):
        """Test basic attack vector prompt generation."""
        code = """def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(query)"""
        pattern = "SQL Injection"
        prompt = PromptTemplates.generate_attack_vector(code, pattern)

        assert "SQL Injection" in prompt
        assert code in prompt
        assert "Attack Vector" in prompt
        assert "SYSTEM_PROMPT" not in prompt
        assert "Example 1:" in prompt
        assert "Example 2:" in prompt

    def test_generate_attack_vector_with_context(self):
        """Test attack vector prompt generation with context."""
        code = "return jsonify(eval(request.json['data']))"
        pattern = "Code Injection"
        context = {
            "file": "app.py",
            "line": 42,
            "function": "process_data",
            "entry_point": "/api/process",
        }
        prompt = PromptTemplates.generate_attack_vector(code, pattern, context)

        assert "Code Injection" in prompt
        assert code in prompt
        assert "file: app.py" in prompt
        assert "function: process_data" in prompt
        assert "entry_point: /api/process" in prompt

    def test_generate_attack_vector_no_context(self):
        """Test attack vector prompt generation without context."""
        code = "os.system(user_input)"
        pattern = "Command Injection"
        prompt = PromptTemplates.generate_attack_vector(code, pattern)

        assert "Command Injection" in prompt
        assert code in prompt
        assert "Context:" not in prompt or prompt.count("Context:") == 0

    def test_explain_vulnerability_basic(self):
        """Test basic vulnerability explanation prompt generation."""
        code = """def authenticate(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query).fetchone()
    return user is not None"""
        finding = {
            "title": "SQL Injection in authentication",
            "severity": "critical",
            "cwe": "CWE-89",
            "confidence": "high",
        }
        prompt = PromptTemplates.explain_vulnerability(code, finding)

        assert "SQL Injection in authentication" in prompt
        assert "severity: critical" in prompt
        assert "cwe: CWE-89" in prompt
        assert code in prompt
        assert "Vulnerability Finding:" in prompt

    def test_explain_vulnerability_minimal_finding(self):
        """Test vulnerability explanation with minimal finding details."""
        code = "return jsonify(eval(user_input))"
        finding = {"title": "Code Injection"}
        prompt = PromptTemplates.explain_vulnerability(code, finding)

        assert "Code Injection" in prompt
        assert code in prompt
        assert "title: Code Injection" in prompt

    def test_suggest_remediation_basic(self):
        """Test basic remediation suggestion prompt generation."""
        code = """def get_user(username):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(query)"""
        pattern = "SQL Injection"
        prompt = PromptTemplates.suggest_remediation(code, pattern)

        assert "SQL Injection" in prompt
        assert code in prompt
        assert "Language: python" in prompt
        assert "Remediation Code:" in prompt
        assert "```python" in prompt
        assert "Vulnerability:" in prompt
        assert "Example 1:" in prompt
        assert "Example 2:" in prompt

    def test_suggest_remediation_custom_language(self):
        """Test remediation suggestion with custom language."""
        code = "const query = `SELECT * FROM users WHERE username='${username}'`"
        pattern = "SQL Injection"
        prompt = PromptTemplates.suggest_remediation(code, pattern, language="javascript")

        assert "SQL Injection" in prompt
        assert "Language: javascript" in prompt
        assert "```javascript" in prompt

    def test_generate_business_logic_abuse_basic(self):
        """Test basic business logic abuse prompt generation."""
        code = """def purchase_item(user_id, item_id, quantity):
    item = get_item(item_id)
    if item.price * quantity > 10000:
        raise ValueError("Purchase too large")
    process_payment(user_id, item.price * quantity)
    ship_item(user_id, item_id, quantity)"""
        context = {"file": "orders.py", "function": "purchase_item", "route": "/api/purchase"}
        prompt = PromptTemplates.generate_business_logic_abuse(code, context)

        assert "file: orders.py" in prompt
        assert "function: purchase_item" in prompt
        assert "route: /api/purchase" in prompt
        assert code in prompt
        assert "Business Logic:" in prompt
        assert "Abuse Scenario" in prompt
        assert "Business Impact:" in prompt
        assert "business logic vulnerabilities" in prompt.lower()

    def test_generate_business_logic_abuse_with_rules(self):
        """Test business logic abuse prompt with business rules."""
        code = "def update_cart(user_id, item_id, quantity): pass"
        context = {"function": "update_cart"}
        business_rules = [
            "Users cannot purchase more than 10 items per day",
            "Item quantities must be positive",
            "Discount codes cannot be combined",
        ]
        prompt = PromptTemplates.generate_business_logic_abuse(code, context, business_rules)

        assert code in prompt
        assert "Users cannot purchase more than 10 items per day" in prompt
        assert "Item quantities must be positive" in prompt
        assert "Discount codes cannot be combined" in prompt
        assert "Business Rules:" in prompt

    def test_format_code_snippet_short(self):
        """Test code snippet formatting for short code."""
        code = "def foo(): return 42"
        formatted = PromptTemplates._format_code_snippet(code)

        assert formatted == "def foo(): return 42"
        assert "(truncated)" not in formatted

    def test_format_code_snippet_long(self):
        """Test code snippet formatting for long code."""
        lines = ["def long_function():"]
        for i in range(150):
            lines.append(f"    x = {i}")
        code = "\n".join(lines)
        formatted = PromptTemplates._format_code_snippet(code, max_lines=100)

        assert "(truncated)" in formatted
        assert formatted.count("\n") <= 101  # 100 lines + truncation marker

    def test_format_context_simple(self):
        """Test context formatting with simple values."""
        context = {"file": "app.py", "line": 42, "function": "login"}
        formatted = PromptTemplates._format_context(context)

        assert "file: app.py" in formatted
        assert "line: 42" in formatted
        assert "function: login" in formatted

    def test_format_context_empty(self):
        """Test context formatting with empty dict."""
        formatted = PromptTemplates._format_context({})
        assert formatted == ""

    def test_format_context_with_list(self):
        """Test context formatting with list value."""
        context = {"files": ["app.py", "utils.py"]}
        formatted = PromptTemplates._format_context(context)

        assert "files: " in formatted
        assert "app.py" in formatted
        assert "utils.py" in formatted

    def test_format_finding_comprehensive(self):
        """Test finding formatting with comprehensive details."""
        finding = {
            "title": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A1:2017-Injection",
            "confidence": "high",
            "code_snippet": "SELECT * FROM users WHERE username='...'",  # Should be excluded
        }
        formatted = PromptTemplates._format_finding(finding)

        assert "title: SQL Injection" in formatted
        assert "severity: critical" in formatted
        assert "cwe: CWE-89" in formatted
        assert "owasp: A1:2017-Injection" in formatted
        assert "confidence: high" in formatted
        assert "code_snippet" not in formatted  # Should exclude code_snippet

    def test_format_finding_empty(self):
        """Test finding formatting with empty dict."""
        formatted = PromptTemplates._format_finding({})
        assert formatted == "No additional details"

    def test_gather_context_minimal(self):
        """Test context gathering with minimal parameters."""
        context = PromptTemplates.gather_context("app.py", 42)
        assert context == {"file": "app.py", "line": 42}

    def test_gather_context_with_function(self):
        """Test context gathering with function name."""
        context = PromptTemplates.gather_context("app.py", 42, "login")
        assert context == {"file": "app.py", "line": 42, "function": "login"}

    def test_gather_context_with_class(self):
        """Test context gathering with class name."""
        context = PromptTemplates.gather_context("app.py", 42, "login", "AuthManager")
        assert context == {
            "file": "app.py",
            "line": 42,
            "function": "login",
            "class": "AuthManager",
        }

    def test_few_shot_attack_examples_in_prompt(self):
        """Test that few-shot attack examples are included in prompts."""
        code = "return eval(user_input)"
        pattern = "Code Injection"
        prompt = PromptTemplates.generate_attack_vector(code, pattern)

        assert "admin' OR '1'='1'" in prompt
        assert "__import__('os').system" in prompt
        assert "Example 1:" in prompt
        assert "Example 2:" in prompt

    def test_few_shot_remediation_examples_in_prompt(self):
        """Test that few-shot remediation examples are included in prompts."""
        code = "query = f\"SELECT * FROM users WHERE username='{username}'\""
        pattern = "SQL Injection"
        prompt = PromptTemplates.suggest_remediation(code, pattern)

        assert "cursor.execute" in prompt
        assert "%s" in prompt
        assert "Example 1:" in prompt
        assert "Example 2:" in prompt
        assert "json.loads" in prompt

    def test_system_prompt_in_all_prompts(self):
        """Test that system prompt is included in all prompt types."""
        code = "def foo(): pass"
        pattern = "Test Pattern"
        finding = {"title": "Test Finding"}
        context = {}

        attack_prompt = PromptTemplates.generate_attack_vector(code, pattern, context)
        explanation_prompt = PromptTemplates.explain_vulnerability(code, finding)
        remediation_prompt = PromptTemplates.suggest_remediation(code, pattern)
        business_logic_prompt = PromptTemplates.generate_business_logic_abuse(code, context)

        assert "expert security analyst" in attack_prompt
        assert "expert security analyst" in explanation_prompt
        assert "expert security analyst" in remediation_prompt
        assert "expert security analyst" in business_logic_prompt
