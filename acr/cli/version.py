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

"""Version command implementation."""

import sys
import click
from acr import __version__


@click.command()
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Show version information."""
    click.echo(f"Adversarial Code Reviewer v{__version__}")
    click.echo(f"Python {sys.version}")
    click.echo(f"Platform: {sys.platform}")
