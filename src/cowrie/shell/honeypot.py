# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import copy
import os
import re
import shlex
from typing import Any

from twisted.internet import error
from twisted.python import failure, log
from twisted.python.compat import iterbytes

from cowrie.commands import cisco_cli
from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.parser import CommandParser
from cowrie.shell.pipe import PipeProtocol

# Pre-compiled regexes for environment variable expansion
_ENV_BRACE_RE = re.compile(r"^\${([_a-zA-Z0-9]+)}$")
_ENV_SIMPLE_RE = re.compile(r"^\$([_a-zA-Z0-9]+)$")


class HoneyPotShell:
    def __init__(
        self, protocol: Any, interactive: bool = True, redirect: bool = False
    ) -> None:
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        self.cmdpending: list[list[str]] = []
        self.environ: dict[str, str] = copy.copy(protocol.environ)
        if hasattr(protocol.user, "windowSize"):
            self.environ["COLUMNS"] = str(protocol.user.windowSize[1])
            self.environ["LINES"] = str(protocol.user.windowSize[0])
        self.lexer: shlex.shlex | None = None
        self.parser = CommandParser()

        # Initialize Cisco IOS mode if the OS is configured as Cisco IOS,
        # or if the configured prompt looks like a Cisco prompt.
        is_cisco = False
        if CowrieConfig.get("shell", "operating_system", fallback="") == "Cisco IOS":
            is_cisco = True
            
        configured_prompt = CowrieConfig.get("honeypot", "prompt", fallback="").strip()
        if configured_prompt.endswith(">") or configured_prompt.endswith("#"):
            is_cisco = True
            
        if is_cisco:
            hostname = CowrieConfig.get("honeypot", "hostname", fallback="Router")
            if not hasattr(protocol, "cisco_mode"):
                protocol.cisco_mode = "user"
            self._cisco_prompt = f"{hostname}> "

        # this is the first prompt after starting
        self.showPrompt()

    def _is_cisco_mode(self) -> bool:
        """Check if we are in Cisco IOS CLI mode."""
        return getattr(self, "_cisco_prompt", None) is not None

    def _get_cisco_mode(self) -> str:
        """Return the current Cisco CLI mode string."""
        return getattr(self.protocol, "cisco_mode", "user")

    def lineReceived(self, line: str) -> None:
        log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")

        # ----- Cisco IOS mode: abbreviation resolution & error handling -----
        if self._is_cisco_mode():
            self._cisco_lineReceived(line)
            return

        # ----- Standard Linux shell mode ------------------------------------
        self.lexer = shlex.shlex(instream=line, punctuation_chars=True, posix=True)
        # Add these special characters that are not in the default lexer
        self.lexer.wordchars += "@%{}=$:+^,()`"

        tokens: list[str] = []

        while True:
            try:
                tokkie: str | None = self.lexer.get_token()
                # log.msg("tok: %s" % (repr(tok)))

                if tokkie is None:  # self.lexer.eof put None for mypy
                    if tokens:
                        self.cmdpending.append(tokens)
                    break
                else:
                    tok: str = tokkie

                # For now, treat && and || same as ;, just execute without checking return code
                if tok == "&&" or tok == "||":
                    if tokens:
                        self.cmdpending.append(tokens)
                        tokens = []
                        continue
                    else:
                        self.protocol.terminal.write(
                            b"% Invalid input detected at '^' marker.\n"
                        )
                        break
                elif tok == ";":
                    if tokens:
                        self.cmdpending.append(tokens)
                        tokens = []
                    continue
                elif tok == "$?":
                    tok = "0"
                elif tok == "(" or (tok.startswith("(") and not tok.startswith("$(")):
                    # Parentheses can only appear at the start of a command, not in the middle
                    if tokens:
                        # Parentheses in the middle of a command line is a syntax error
                        self.protocol.terminal.write(
                            b"% Invalid input detected at '^' marker.\n"
                        )
                        break
                    if tok == "(":
                        self.do_subshell_execution_from_lexer()
                    else:
                        self.do_subshell_execution(tok)
                    continue
                elif "$(" in tok or "`" in tok:
                    tok = self.do_command_substitution(tok)
                elif tok.startswith("${"):
                    envSearch = _ENV_BRACE_RE.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in self.environ:
                            tok = self.environ[envMatch]
                        else:
                            continue
                elif tok.startswith("$"):
                    envSearch = _ENV_SIMPLE_RE.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in self.environ:
                            tok = self.environ[envMatch]
                        else:
                            continue

                tokens.append(tok)
            except Exception as e:
                self.protocol.terminal.write(
                    b"% Invalid input detected at '^' marker.\n"
                )
                # Could run runCommand here, but i'll just clear the list instead
                log.msg(f"exception: {e}")
                self.cmdpending = []
                self.showPrompt()
                return

        if self.cmdpending:
            # Coalesce fd redirection tokens so we don't treat `2` as a command
            self.cmdpending = [
                self.parser.merge_redirection_tokens(tokens)
                for tokens in self.cmdpending
            ]
            # if we have a complete command, go and run it
            self.runCommand()
        else:
            # if there's no command, display a prompt again
            self.showPrompt()

    def _cisco_lineReceived(self, line: str) -> None:
        """
        Cisco IOS-style line processing:
        - Resolve abbreviated commands (en -> enable, sh ver -> show version)
        - Generate Cisco-style error messages with '^' marker
        - Handle incomplete/ambiguous commands
        """
        stripped = line.strip()
        if not stripped:
            self.showPrompt()
            return

        mode = self._get_cisco_mode()

        # Split into simple tokens (Cisco CLI doesn't use shell quoting)
        tokens = stripped.split()

        # Resolve abbreviations through the command tree
        resolved, error_type, error_idx = cisco_cli.resolve_command_tokens(tokens, mode)

        if error_type == "ambiguous":
            self.protocol.terminal.write(
                cisco_cli.format_ambiguous_error(stripped).encode("utf-8")
            )
            self.showPrompt()
            return

        if error_type == "invalid":
            # Calculate the character position of the bad token
            char_pos = cisco_cli.get_error_char_position(tokens, error_idx, stripped)
            # Show Cisco-style error with ^ marker
            marker = " " * char_pos + "^"
            self.protocol.terminal.write(
                f"% Invalid input detected at '^' marker.\n\n{stripped}\n{marker}\n".encode("utf-8")
            )
            self.showPrompt()
            return

        # Check if command is valid but incomplete (e.g., "show" with no subcommand)
        if error_type is None and cisco_cli.command_needs_subcommand(resolved, mode):
            self.protocol.terminal.write(
                cisco_cli.format_incomplete_error().encode("utf-8")
            )
            self.showPrompt()
            return

        # Successfully resolved — put the resolved tokens in the pending queue
        self.cmdpending.append(resolved)

        if self.cmdpending:
            self.runCommand()
        else:
            self.showPrompt()

    def do_subshell_execution_from_lexer(self) -> None:
        """
        Execute a subshell command reading tokens from the lexer until matching closing parenthesis.
        Output goes directly to the terminal.
        """
        cmd_tokens = []
        opening_count = 1
        closing_count = 0

        while opening_count > closing_count:
            if self.lexer is None:
                break
            tok = self.lexer.get_token()
            if tok is None:
                break

            if tok == ")":
                closing_count += 1
                if opening_count == closing_count:
                    break
                else:
                    cmd_tokens.append(tok)
            elif tok == "(":
                opening_count += 1
                cmd_tokens.append(tok)
            else:
                cmd_tokens.append(tok)

        # execute the command and print to terminal
        cmd_str = " ".join(cmd_tokens)
        self.protocol.terminal.write(self.run_subshell_command(f"({cmd_str})").encode())

    def do_subshell_execution(self, start_tok: str) -> None:
        """
        Execute a subshell command (command) without output substitution.
        Output goes directly to the terminal.
        """
        if start_tok[0] == "(":
            cmd_expr = start_tok
            pos = 1
            opening_count = 1
            closing_count = 0

            # parse the remaining tokens to find the matching closing parenthesis
            while opening_count > closing_count:
                if cmd_expr[pos] == ")":
                    closing_count += 1
                    if opening_count == closing_count:
                        # execute the command in () and print to terminal
                        self.protocol.terminal.write(
                            self.run_subshell_command(cmd_expr[: pos + 1]).encode()
                        )
                        break
                    else:
                        pos += 1
                elif cmd_expr[pos] == "(":
                    opening_count += 1
                    pos += 1
                else:
                    if opening_count > closing_count and pos == len(cmd_expr) - 1:
                        if self.lexer:
                            tokkie = self.lexer.get_token()
                            if tokkie is None:  # self.lexer.eof put None for mypy
                                break
                            else:
                                cmd_expr = cmd_expr + " " + tokkie
                    pos += 1

    def do_command_substitution(self, start_tok: str) -> str:
        """
        Perform command substitution, replacing $(cmd) or `cmd` with output.
        """
        result = ""
        if start_tok[0] == "(":
            cmd_expr = start_tok
            pos = 1
        elif "$(" in start_tok:
            dollar_pos = start_tok.index("$(")
            result = start_tok[:dollar_pos]
            cmd_expr = start_tok[dollar_pos:]
            pos = 2
        elif "`" in start_tok:
            backtick_pos = start_tok.index("`")
            result = start_tok[:backtick_pos]
            cmd_expr = start_tok[backtick_pos:]
            pos = 1
        else:
            log.msg(f"failed command substitution: {start_tok}")
            return start_tok

        opening_count = 1
        closing_count = 0

        while opening_count > closing_count:
            if cmd_expr[pos] in (")", "`"):
                closing_count += 1
                if opening_count == closing_count:
                    if cmd_expr[0] == "(":
                        self.protocol.terminal.write(
                            self.run_subshell_command(cmd_expr[: pos + 1]).encode()
                        )
                    else:
                        result += self.run_subshell_command(cmd_expr[: pos + 1])

                    if pos < len(cmd_expr) - 1:
                        remainder = cmd_expr[pos + 1 :]
                        if "$(" in remainder or "`" in remainder:
                            result = self.do_command_substitution(result + remainder)
                        else:
                            result += remainder
                else:
                    pos += 1
            elif cmd_expr[pos : pos + 2] == "$(":
                opening_count += 1
                pos += 2
            else:
                if opening_count > closing_count and pos == len(cmd_expr) - 1:
                    if self.lexer:
                        tokkie = self.lexer.get_token()
                        if tokkie is None:
                            break
                        else:
                            cmd_expr = cmd_expr + " " + tokkie
                pos += 1

        return result

    def run_subshell_command(self, cmd_expr: str) -> str:
        # extract the command from $(...) or `...` or (...) expression
        if cmd_expr.startswith("$("):
            cmd = cmd_expr[2:-1]
        else:
            cmd = cmd_expr[1:-1]

        # For subshells with multiple commands, we need to capture all output
        # Create a custom output accumulator
        if cmd_expr.startswith("("):
            return self._execute_subshell_with_full_output(cmd)
        else:
            # Command substitution - use existing method
            return self._execute_command_substitution(cmd)

    def _execute_subshell_with_full_output(self, cmd: str) -> str:
        """Execute subshell commands and capture ALL output, not just the last command."""
        # Split commands by separators and execute each one
        lexer = shlex.shlex(instream=cmd, punctuation_chars=True, posix=True)
        lexer.wordchars += "@%{}=$:+^,()`"

        accumulated_output = ""
        current_cmd_tokens: list[str] = []

        while True:
            tok = lexer.get_token()
            if tok is None:
                # Process final command
                if current_cmd_tokens:
                    cmd_str = " ".join(current_cmd_tokens)
                    output = self._execute_single_command_with_redirect(cmd_str)
                    accumulated_output += output
                break
            elif tok in (";", "&&", "||"):
                # Process current command and start new one
                if current_cmd_tokens:
                    cmd_str = " ".join(current_cmd_tokens)
                    output = self._execute_single_command_with_redirect(cmd_str)
                    accumulated_output += output
                    current_cmd_tokens = []
                # Note: We're ignoring && and || conditional logic for now
            else:
                current_cmd_tokens.append(tok)

        return accumulated_output

    def _execute_command_substitution(self, cmd: str) -> str:
        """Execute command substitution - should capture all output."""
        # Command substitution should also capture all output from multiple commands
        output = self._execute_subshell_with_full_output(cmd)
        # trailing newlines are stripped for command substitution
        return output.rstrip("\n")

    def _execute_single_command_with_redirect(self, cmd: str) -> str:
        """Execute a single command and return its output."""
        # instantiate new shell with redirect output
        self.protocol.cmdstack.append(
            HoneyPotShell(self.protocol, interactive=False, redirect=True)
        )
        # call lineReceived method that indicates that we have some commands to parse
        self.protocol.cmdstack[-1].lineReceived(cmd)
        # and remove the shell
        res = self.protocol.cmdstack.pop()

        try:
            output: str = res.protocol.pp.redirected_data.decode()
        except AttributeError:
            return ""
        else:
            return output

    def runCommand(self):
        pp = None

        def runOrPrompt() -> None:
            if self.cmdpending:
                self.runCommand()
            else:
                self.showPrompt()

        if not self.cmdpending:
            if self.protocol.pp.next_command is None:  # command dont have pipe(s)
                if self.interactive:
                    self.showPrompt()
                else:
                    # when commands passed to a shell via PIPE, we spawn a HoneyPotShell in none interactive mode
                    # if there are another shells on stack (cmdstack), let's just exit our new shell
                    # else close connection
                    if len(self.protocol.cmdstack) == 1:
                        ret = failure.Failure(error.ProcessDone(status=""))
                        self.protocol.terminal.transport.processEnded(ret)
                    else:
                        return
            else:
                pass  # command with pipes
            return

        cmdAndArgs = self.cmdpending.pop(0)

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_tokens: list[str] = []
        cmd_array: list[dict[str, Any]] = []
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if piece.count("="):
                key, val = piece.split("=", 1)
                environ[key] = val
                continue
            cmd_tokens = [piece, *cmdAndArgs]
            break

        if not cmd_tokens:
            runOrPrompt()
            return

        pipe_indices = [i for i, x in enumerate(cmd_tokens) if x == "|"]
        multipleCmdArgs: list[list[str]] = []
        pipe_indices.append(len(cmd_tokens))
        start = 0

        # Gather all arguments with pipes

        for _index, pipe_indice in enumerate(pipe_indices):
            multipleCmdArgs.append(cmd_tokens[start:pipe_indice])
            start = pipe_indice + 1

        first_args, first_ops = self.parser.parse_redirections(multipleCmdArgs.pop(0))
        if not first_args:
            if first_ops:
                # Handle redirection without command (e.g. > file)
                pp = PipeProtocol(
                    self.protocol,
                    None,
                    [],
                    None,
                    None,
                    self.redirect,
                    first_ops,
                )
                # This triggers _setup_redirections which creates files
            runOrPrompt()
            return

        cmd_array.append(
            {
                "command": first_args.pop(0),
                "rargs": first_args,
                "redirects": first_ops,
            }
        )

        for cmd_args in multipleCmdArgs:
            args, ops = self.parser.parse_redirections(cmd_args)
            if not args:
                continue
            cmd_array.append(
                {
                    "command": args.pop(0),
                    "rargs": args,
                    "redirects": ops,
                }
            )

        lastpp = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            cmdclass = self.protocol.getCommand(
                cmd["command"], environ["PATH"].split(":")
            )
            if cmdclass:
                log.msg(
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command found: %(input)s",
                )
                if index == len(cmd_array) - 1:
                    lastpp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        None,
                        self.redirect,
                        cmd.get("redirects", []),
                    )
                    pp = lastpp
                else:
                    pp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        lastpp,
                        self.redirect,
                        cmd.get("redirects", []),
                    )
                    lastpp = pp
            else:
                log.msg(
                    eventid="cowrie.command.failed",
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command not found: %(input)s",
                )
                message = b"% Unknown command or computer name, or unable to find computer address\n"
                redirects = cmd.get("redirects", [])
                if redirects:
                    temp_pp = PipeProtocol(
                        self.protocol,
                        None,
                        [],
                        None,
                        None,
                        self.redirect,
                        redirects,
                    )
                    temp_pp.errReceived(message)
                    for real_path, virtual_path in temp_pp.redirect_real_files:
                        self.protocol.terminal.redirFiles.add((real_path, virtual_path))
                else:
                    self.protocol.terminal.write(message)

                # Import here to avoid circular dependency with protocol module
                from cowrie.shell import protocol

                if (
                    isinstance(self.protocol, protocol.HoneyPotExecProtocol)
                    and not self.cmdpending
                ):
                    exit_status = failure.Failure(error.ProcessDone(status=""))
                    self.protocol.terminal.transport.processEnded(exit_status)

                runOrPrompt()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp and getattr(pp, "has_redirection_error", False):
            runOrPrompt()
            return

        if pp:
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]["rargs"])

    def resume(self) -> None:
        if self.interactive:
            self.protocol.setInsertMode()
        self.runCommand()

    def showPrompt(self) -> None:
        if not self.interactive:
            return

        prompt = ""
        # Check for Cisco-style dynamic prompt (set by enable/configure commands)
        cisco_prompt = getattr(self, "_cisco_prompt", None)
        if cisco_prompt:
            prompt = cisco_prompt
        elif CowrieConfig.has_option("honeypot", "prompt"):
            prompt = CowrieConfig.get("honeypot", "prompt")
            prompt += " "
        else:
            cwd = self.protocol.cwd
            homelen = len(self.protocol.user.avatar.home)
            if cwd == self.protocol.user.avatar.home:
                cwd = "~"
            elif (
                len(cwd) > (homelen + 1)
                and cwd[: (homelen + 1)] == self.protocol.user.avatar.home + "/"
            ):
                cwd = "~" + cwd[homelen:]

            # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
            # Example: root@svr03:~#     (More of a "Debian" feel)
            prompt = f"{self.protocol.user.username}@{self.protocol.hostname}:{cwd}"
            if not self.protocol.user.uid:
                prompt += "# "  # "Root" user
            else:
                prompt += "$ "  # "Non-Root" user

        self.protocol.terminal.write(prompt.encode("ascii"))
        self.protocol.ps = (prompt.encode("ascii"), b"> ")

    def eofReceived(self) -> None:
        """
        this should probably not go through ctrl-d, but use processprotocol to close stdin
        """
        log.msg("received eof, sending ctrl-d to command")
        if self.protocol.cmdstack:
            self.protocol.cmdstack[-1].handle_CTRL_D()

    def handle_CTRL_C(self) -> None:
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"\n")
        self.showPrompt()

    def handle_CTRL_D(self) -> None:
        log.msg("Received CTRL-D, exiting..")
        status = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(status)

    def handle_TAB(self) -> None:
        """
        lineBuffer is an array of bytes
        """
        if not self.protocol.lineBuffer:
            return

        line: bytes = b"".join(self.protocol.lineBuffer)

        # ----- Cisco IOS tab completion -----
        if self._is_cisco_mode():
            self._cisco_handle_TAB(line)
            return

        # ----- Standard Linux filesystem tab completion -----
        if line[-1:] == b" ":
            clue = ""
        else:
            clue = line.split()[-1].decode("utf8")

        # clue now contains the string to complete or is empty.
        # line contains the buffer as bytes
        basedir = os.path.dirname(clue)
        if basedir and basedir[-1] != "/":
            basedir += "/"

        if not basedir:
            tmppath = self.protocol.cwd
        else:
            tmppath = basedir

        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except Exception:
            return

        if not self.protocol.fs.exists(r):
            return

        files = []
        for x in self.protocol.fs.get_path(r):
            if clue == "":
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if not files:
            return

        # Clear early so we can call showPrompt if needed
        for _i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ""
        if len(files) == 1:
            newbuf = " ".join(
                [*line.decode("utf8").split()[:-1], f"{basedir}{files[0][fs.A_NAME]}"]
            )
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += "/"
            else:
                newbuf += " "
            newbyt = newbuf.encode("utf8")
        else:
            if os.path.basename(clue):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ""
            first = line.decode("utf8").split(" ")[:-1]
            newbuf = " ".join([*first, f"{basedir}{prefix}"])
            newbyt = newbuf.encode("utf8")
            if newbyt == b"".join(self.protocol.lineBuffer):
                self.protocol.terminal.write(b"\n")
                maxlen = max(len(x[fs.A_NAME]) for x in files) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write(b"\n")
                    self.protocol.terminal.write(
                        file[fs.A_NAME].ljust(maxlen).encode("utf8")
                    )
                    count += 1
                self.protocol.terminal.write(b"\n")
                self.showPrompt()

        self.protocol.lineBuffer = [y for x, y in enumerate(iterbytes(newbyt))]
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbyt)

    def _cisco_handle_TAB(self, line: bytes) -> None:
        """
        Cisco IOS-style tab completion:
        - Single match: expand to full keyword + space
        - Multiple matches: do nothing (just beep, like real Cisco)
        - No match: do nothing
        """
        line_str = line.decode("utf-8")
        mode = self._get_cisco_mode()

        completed, candidates = cisco_cli.complete_command(line_str, mode)

        if completed:
            # Clear the current line from the terminal
            for _i in range(self.protocol.lineBufferIndex):
                self.protocol.terminal.cursorBackward()
                self.protocol.terminal.deleteCharacter()

            newbyt = completed.encode("utf-8")
            self.protocol.lineBuffer = [y for x, y in enumerate(iterbytes(newbyt))]
            self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
            self.protocol.terminal.write(newbyt)
        elif len(candidates) > 1:
            # Multiple matches — Cisco beeps (sends BEL) or shows nothing
            # Real Cisco IOS just does nothing on Tab with ambiguous input
            self.protocol.terminal.write(b"\x07")  # BEL character
        # else: no matches — do nothing

    def cisco_handle_question(self, line_str: str) -> None:
        """
        Handle '?' inline help for Cisco IOS mode.
        Called from protocol.py when '?' is typed.
        """
        mode = self._get_cisco_mode()
        help_text = cisco_cli.get_help(line_str, mode)
        self.protocol.terminal.write(b"\n")
        self.protocol.terminal.write(help_text.encode("utf-8"))
        self.showPrompt()
        # Re-display what the user had typed before '?'
        if line_str.strip():
            line_bytes = line_str.encode("utf-8")
            self.protocol.terminal.write(line_bytes)
            self.protocol.lineBuffer = [y for x, y in enumerate(iterbytes(line_bytes))]
            self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
