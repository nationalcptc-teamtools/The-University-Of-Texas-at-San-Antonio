"""Metasploit-style terminal UI backed by the same modules as direct commands."""

import shlex
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from rich.console import Console
from rich.table import Table

from fieldkit import __version__
from fieldkit.registry import modules

HELP = """Commands:
  modules / search [text]     List or filter modules
  use <module>               Select a module
  info                       Describe the selected module
  options / show options     Display current settings
  set <OPTION> <value>        Set an option (lists use spaces; quote paths)
  unset <OPTION>             Restore an option's default
  run                        Run the selected module
  back                       Leave the selected module
  help                       Show this help
  exit / quit                Exit the console

Example: use web/artifacts
         set TARGETS localhost 127.0.0.1:8080
         set SCHEME http
         run
"""


class InteractiveConsole:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.registry = modules()
        self.selected: str | None = None
        self.settings = {name: module.defaults() for name, module in self.registry.items()}

    def run(self) -> int:
        self.console.print(f"Fieldkit {__version__}", style="bold cyan")
        self.console.print("Type 'help' for commands, or 'use web/artifacts' to begin.")
        words = [
            "modules",
            "search",
            "use",
            "info",
            "options",
            "show",
            "set",
            "unset",
            "run",
            "back",
            "help",
            "exit",
            "quit",
            *self.registry,
            *(o.name for m in self.registry.values() for o in m.options),
        ]
        session: PromptSession | None = None
        if sys.stdin.isatty():
            session = PromptSession(completer=WordCompleter(words, ignore_case=True))
        while True:
            prompt = f"fieldkit{f' ({self.selected})' if self.selected else ''} > "
            try:
                line = session.prompt(prompt) if session else input(prompt)
                if not self.execute(line):
                    return 0
            except EOFError:
                return 0
            except KeyboardInterrupt:
                self.console.print("\nInput cancelled. Type 'exit' to leave.")
            except (ValueError, OSError) as exc:
                self.console.print(f"Error: {exc}", style="red", markup=False)

    def execute(self, line: str) -> bool:
        parts = shlex.split(line)
        if not parts:
            return True
        command, *args = parts
        command = command.lower()
        if command in {"exit", "quit"}:
            return False
        if command == "help":
            self.console.print(HELP, markup=False)
        elif command in {"modules", "search"}:
            query = " ".join(args).lower()
            for name, module in self.registry.items():
                if query in f"{name} {module.description}".lower():
                    self.console.print(f"{name:<24} {module.description}", markup=False)
        elif command == "use":
            if len(args) != 1 or args[0] not in self.registry:
                raise ValueError("Use 'modules' to find a module, then 'use <module>'")
            self.selected = args[0]
            self.show_options()
        elif command == "back":
            self.selected = None
        elif command in {"info", "options", "show", "set", "unset", "run"}:
            if self.selected is None:
                raise ValueError("Select a module first with 'use <module>'")
            module = self.registry[self.selected]
            settings = self.settings[self.selected]
            if command == "info":
                self.console.print(module.description)
                self.show_options()
            elif command in {"options", "show"}:
                if command == "show" and args != ["options"]:
                    raise ValueError("Usage: show options")
                self.show_options()
            elif command in {"set", "unset"}:
                options = {o.name: o for o in module.options}
                if not args or args[0].upper() not in options:
                    raise ValueError("Unknown option. Use 'options' to see available settings")
                name = args[0].upper()
                if command == "unset":
                    settings[name] = module.defaults()[name]
                elif len(args) < 2:
                    raise ValueError("Usage: set <OPTION> <value>")
                elif options[name].kind is list:
                    settings[name] = args[1:]
                else:
                    settings[name] = options[name].parse(" ".join(args[1:]))
                self.console.print(f"{name} => {settings[name]}", markup=False)
            elif command == "run":
                code = module.run(settings.copy(), self.console)
                self.console.print(f"Module finished (exit status {code}).")
        else:
            raise ValueError(f"Unknown command: {command}. Type 'help' for commands")
        return True

    def show_options(self) -> None:
        if self.selected is None:
            raise ValueError("Select a module first")
        table = Table(title=self.selected)
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Value", overflow="fold")
        table.add_column("Description")
        for option in self.registry[self.selected].options:
            value = self.settings[self.selected][option.name]
            table.add_row(option.name, str(value), option.description)
        self.console.print(table)
