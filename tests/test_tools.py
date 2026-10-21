"""The MCP tools' safety rules and their timing semantics, against a fake tmux."""

import time
import unittest

import anyio

from bon5ai_remote import mcp_server
from bon5ai_remote.agents import Grant
from bon5ai_remote.mcp_server import Tools, ToolError, check_text
from helpers import FakeTmux, make_pane, make_state


def grant(scope="control", pane="%1") -> Grant:
    return Grant(id="g-00000001", session_key="$1@100", pane_id=pane, scope=scope, client_id="c",
                 client_name="Test", verified=False, resources=frozenset(), created=0, expires=time.time() + 3600)


class ToolCase(unittest.TestCase):
    def setUp(self):
        self.tmux = FakeTmux()
        self.state = make_state(tmux=self.tmux)
        self.foreground = {}  # pane pid -> foreground process group; default: the shell
        self._fg = mcp_server.foreground_pgid
        mcp_server.foreground_pgid = lambda pid: self.foreground.get(pid, pid)

    def tearDown(self):
        mcp_server.foreground_pgid = self._fg

    def call(self, name, args, scope="control"):
        tools = Tools(self.state, grant(scope))
        return anyio.run(getattr(tools, name), args)

    def refused(self, name, args, code, scope="control"):
        with self.assertRaises(ToolError) as caught:
            self.call(name, args, scope)
        self.assertEqual(caught.exception.code, code)
        return caught.exception


class TextRuleTests(unittest.TestCase):
    def test_refuses_what_could_drive_the_terminal_or_mislead_a_reviewer(self):
        for text in ("\x1b[201~rm -rf ~", "a\x03", "a\rb", "x\x7f", "ls‮", "ls​", "a b", "",
                     "\ud800", "\x9b31m", "rm -rf", "ls　-la"):  # no-break and ideographic spaces
            with self.assertRaises(ToolError, msg=repr(text)):
                check_text(text, allow_newlines=True)
        with self.assertRaises(ToolError):
            check_text("one\ntwo", allow_newlines=False)
        with self.assertRaises(ToolError):
            check_text("x" * 5000, allow_newlines=False)

    def test_accepts_ordinary_text(self):
        for text in ("ls -la", "-R", "echo a;", "find . -exec rm {} \\;", "naïve 日本語 ✓", "a\tb"):
            self.assertEqual(check_text(text, allow_newlines=False), text)


class WriteRuleTests(ToolCase):
    def test_types_literally(self):
        self.call("send_text", {"text": "-R"})
        self.assertEqual(self.tmux.writes, [("text", "%1", "-R")])

    def test_suggest_types_but_never_submits(self):
        self.call("send_text", {"text": "git status"}, scope="suggest")
        self.assertEqual(self.tmux.writes, [("text", "%1", "git status")])
        self.refused("send_text", {"text": "git push", "submit": True}, "needs_control", scope="suggest")
        self.refused("send_text", {"text": "a\nb"}, "needs_control", scope="suggest")

    def test_suggest_needs_a_shell_prompt(self):
        self.foreground[4242] = 999  # something else owns the terminal (a pager, a y/N prompt…)
        self.refused("send_text", {"text": "q"}, "not_at_prompt", scope="suggest")
        self.foreground.clear()
        self.tmux.panes_by_id["%1"] = make_pane(alternate_on=True, command="vim")
        self.refused("send_text", {"text": "dd"}, "not_at_prompt", scope="suggest")
        self.assertEqual(self.tmux.writes, [])

    def test_suggest_refuses_tab_and_panes_that_are_not_a_local_shell(self):
        # Tab runs completion, which can run code before anyone presses Enter.
        self.refused("send_text", {"text": "make \t"}, "invalid_text", scope="suggest")
        # In an ssh pane the local foreground says nothing about the far side.
        self.tmux.panes_by_id["%1"] = make_pane(command="ssh")
        self.refused("send_text", {"text": "y"}, "not_at_prompt", scope="suggest")
        self.tmux.panes_by_id["%1"] = make_pane(command="-zsh")  # a login shell
        self.call("send_text", {"text": "ls"}, scope="suggest")

    def test_control_may_type_into_a_program(self):
        self.tmux.panes_by_id["%1"] = make_pane(alternate_on=True, command="vim")
        self.call("send_text", {"text": "ihello"})
        self.assertEqual(len(self.tmux.writes), 1)

    def test_multiline_is_pasted_and_needs_submit(self):
        self.refused("send_text", {"text": "a\nb"}, "invalid_argument")
        self.call("send_text", {"text": "a\nb", "submit": True})
        self.assertEqual(self.tmux.writes, [("paste", "%1", "a\nb"), ("keys", "%1", ["Enter"])])

    def test_copy_mode_is_refused(self):
        self.tmux.panes_by_id["%1"] = make_pane(in_mode=True)
        self.refused("send_keys", {"keys": ["Enter"]}, "pane_in_mode")

    def test_a_pane_nobody_can_see_is_refused(self):
        self.tmux.panes_by_id["%1"] = make_pane(window_active=False)
        self.refused("send_text", {"text": "ls"}, "pane_not_visible")

    def test_the_person_typing_wins(self):
        self.tmux.human = time.time()
        self.refused("send_text", {"text": "ls"}, "busy_human")
        self.tmux.human = time.time() - 10
        self.call("send_text", {"text": "ls"})

    def test_stale_screen_is_refused(self):
        shot = self.call("read_screen", {})[1]
        self.tmux.screen = ["something new happened"]
        self.refused("send_text", {"text": "y", "if_screen": shot["screen"]}, "conflict")
        fresh = self.call("read_screen", {})[1]["screen"]
        self.call("send_text", {"text": "y", "if_screen": fresh})

    def test_gone_or_foreign_panes(self):
        self.tmux.panes_by_id.clear()
        self.refused("read_screen", {}, "pane_gone")
        self.tmux.panes_by_id["%1"] = make_pane(session_key="$7@1")  # a pane of another session
        self.refused("read_screen", {}, "pane_gone")

    def test_keys_come_from_the_allowlist(self):
        self.refused("send_keys", {"keys": ["C-s"]}, "invalid_argument")
        self.refused("send_keys", {"keys": ["Enter; kill-server"]}, "invalid_argument")
        self.call("send_keys", {"keys": ["C-c", "PageUp", "Delete"]})
        self.assertEqual(self.tmux.writes, [("keys", "%1", ["C-c", "PPage", "DC"])])

    def test_writes_are_rate_limited(self):
        tools = Tools(self.state, grant())
        for _ in range(20):
            anyio.run(tools.send_keys, {"keys": ["Up"]})
        with self.assertRaises(ToolError) as caught:
            anyio.run(tools.send_keys, {"keys": ["Up"]})
        self.assertEqual(caught.exception.code, "rate_limited")


class TimingTests(ToolCase):
    def test_run_command_waits_for_the_shell_and_a_settled_screen(self):
        def run():
            self.tmux.screen = ["someone@box:~$ echo hi", "hi", "someone@box:~$"]
        self.tmux.after_enter = run
        started = time.monotonic()
        text, data = self.call("run_command", {"command": "echo hi", "idle_ms": 200})
        self.assertEqual(data["state"], "done")
        self.assertIn("hi", text)
        self.assertGreaterEqual(time.monotonic() - started, 0.2)

    def test_a_quiet_screen_alone_is_not_done(self):
        # Enter changes nothing and a program owns the terminal: still running, not done.
        def run():
            self.tmux.screen = ["someone@box:~$ sleep 100", ""]
            self.foreground[4242] = 777
        self.tmux.after_enter = run
        text, data = self.call("run_command", {"command": "sleep 100", "timeout_s": 1, "idle_ms": 200})
        self.assertEqual(data["state"], "running")

    def test_run_command_starts_from_an_empty_line(self):
        self.tmux.after_enter = lambda: self.tmux.screen.append("someone@box:~$")
        self.call("run_command", {"command": "true", "idle_ms": 200, "timeout_s": 1})
        self.assertEqual(self.tmux.writes[:3], [("keys", "%1", ["C-e", "C-u"]), ("text", "%1", "true"),
                                                ("keys", "%1", ["Enter"])])

    def test_run_command_never_presses_enter_on_a_line_it_did_not_type(self):
        self.tmux.send_literal = lambda pane, text: True  # the keys vanish (a program grabbed them)
        self.refused("run_command", {"command": "rm -rf build"}, "typing_mismatch")
        self.assertNotIn(("keys", "%1", ["Enter"]), self.tmux.writes)

    def test_run_command_needs_a_prompt(self):
        self.foreground[4242] = 777
        self.refused("run_command", {"command": "ls"}, "not_at_prompt")

    def test_wait_for_text_and_idle(self):
        self.tmux.screen = ["build: ok"]
        self.assertEqual(self.call("wait_for", {"text": "ok", "timeout_s": 1})[1]["outcome"], "matched")
        self.assertEqual(self.call("wait_for", {"idle_ms": 200, "timeout_s": 1})[1]["outcome"], "idle")
        self.assertEqual(self.call("wait_for", {"text": "never", "timeout_s": 1})[1]["outcome"], "timeout")

    def test_wait_is_capped(self):
        self.refused("wait_for", {"timeout_s": 60}, "invalid_argument")

    def test_history_is_not_read_from_a_full_screen_program(self):
        self.assertIn("scrollback", self.call("read_screen", {"history_lines": 5})[0])
        self.tmux.panes_by_id["%1"] = make_pane(alternate_on=True)
        self.assertNotIn("scrollback", self.call("read_screen", {"history_lines": 5})[0])


if __name__ == "__main__":
    unittest.main()
