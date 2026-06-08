from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.text import Text


TITLE = r"""
████████╗██╗  ██╗███████╗██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
╚══██╔══╝██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
   ██║   ███████║█████╗  ██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
   ██║   ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
   ██║   ██║  ██║███████╗██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   
"""

DRAGON_CORE = r"""
                  ╭────────────────────────────────────────────╮
                  │                                            │
                  │        /\_/\______/\_/\                    │
                  │       /  _   CYBER   _  \                  │
                  │      /  / \  DRAGON / \  \                 │
                  │     |  |   | ACTIVE |   |  |                │
                  │      \  \_/  ______  \_/  /                 │
                  │       \_____/      \_____/                  │
                  │            \  /\  /\  /                     │
                  │             \/  \/  \/                      │
                  │                                            │
                  ╰────────────────────────────────────────────╯
"""


def print_banner(console):
    title = Text(TITLE, style="bold bright_cyan")
    dragon = Text(DRAGON_CORE, style="bold cyan")

    tagline = Text()
    tagline.append("Evidence-Based Bug Bounty Triage Scanner", style="bold green")

    author = Text()
    author.append("by ", style="bold white")
    author.append("Suspecting", style="bold bright_magenta")
    author.append("  •  ", style="bold white")
    author.append("github.com/suspecting", style="bold cyan")

    version = Text()
    version.append("Version: ", style="bold white")
    version.append("1.0.0", style="bold cyan")
    version.append("  |  ")
    version.append("Mode: ", style="bold white")
    version.append("Authorized Security Testing", style="bold yellow")

    modules = Text()
    modules.append("[ ", style="bold white")
    modules.append("SCOPE ENGINE", style="bold yellow")
    modules.append(" ]  [ ", style="bold white")
    modules.append("JS RECON", style="bold cyan")
    modules.append(" ]  [ ", style="bold white")
    modules.append("XSS / SQLi INDICATORS", style="bold magenta")
    modules.append(" ]  [ ", style="bold white")
    modules.append("BUG BOUNTY REPORTS", style="bold green")
    modules.append(" ]", style="bold white")

    warning = Text()
    warning.append("AUTHORIZED TARGETS ONLY", style="bold red")
    warning.append("  •  Stay in scope  •  Passive-first  •  No reckless scanning", style="bold white")

    group = Group(
        Align.center(dragon),
        Align.center(title),
        Align.center(tagline),
        Align.center(author),
        Align.center(version),
        Align.center(modules),
        Align.center(warning),
    )

    console.print(
        Panel(
            group,
            title="[bold bright_cyan] thebugbounty [/bold bright_cyan]",
            subtitle="[bold bright_magenta] made by Suspecting • github.com/Suspecting [/bold bright_magenta]",
            border_style="bright_cyan",
            padding=(1, 2)
        )
    )
