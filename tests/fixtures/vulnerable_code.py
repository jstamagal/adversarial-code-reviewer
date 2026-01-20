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

"""Test file with SQL injection vulnerability."""


def vulnerable_function(user_input):
    """Function with SQL injection vulnerability."""
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()


def another_vulnerable_function(username):
    """Another SQL injection using f-string."""
    query = f"SELECT * FROM users WHERE username='{username}'"
    cursor.execute(query)
    return cursor.fetchall()


def secure_function(user_input):
    """Secure version using parameterized query."""
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()
