"""Configuration refuses unsafe setups instead of running them quietly."""

import os
import tempfile
import unittest
from pathlib import Path

from bon5ai_remote.config import ConfigError, ensure_private_dir, load


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.env = {"XDG_CONFIG_HOME": str(self.dir / "config"), "XDG_STATE_HOME": str(self.dir / "state"),
                    "XDG_RUNTIME_DIR": str(self.dir / "run")}

    def tearDown(self):
        self.tmp.cleanup()

    def load(self, text: str, **env):
        path = self.dir / "config.toml"
        path.write_text(text)
        return load(path, env={**self.env, **env})

    def test_defaults_without_a_file(self):
        cfg = load(env=self.env)
        self.assertEqual(cfg.session, "share")
        self.assertEqual(cfg.tmux_socket, self.dir / "run" / "bon5ai-remote" / "tmux.sock")
        self.assertEqual(cfg.admin_socket, self.dir / "run" / "bon5ai-remote" / "admin.sock")
        listener = cfg.listeners[0]
        self.assertEqual((listener.host, listener.port), ("127.0.0.1", 8095))
        self.assertEqual(listener.public_url, "http://127.0.0.1:8095/")

    def test_viewer_resize_is_off_unless_turned_on(self):
        self.assertFalse(load(env=self.env).viewer_resize)
        self.assertTrue(self.load("viewer_resize = true\n").viewer_resize)
        with self.assertRaisesRegex(ConfigError, "viewer_resize must be true or false"):
            self.load('viewer_resize = "yes"\n')

    def test_listener_must_be_loopback(self):
        with self.assertRaisesRegex(ConfigError, "must be loopback"):
            self.load('[[listener]]\naddress = "0.0.0.0:8095"\n')
        with self.assertRaisesRegex(ConfigError, "must be loopback"):
            self.load('[[listener]]\naddress = "172.18.0.1:8095"\n')

    def test_private_listen_is_opt_in_and_never_unspecified(self):
        cfg = self.load('allow_private_listen = true\n[[listener]]\naddress = "172.18.0.1:8095"\n')
        self.assertEqual(cfg.listeners[0].host, "172.18.0.1")
        with self.assertRaises(ConfigError):
            self.load('allow_private_listen = true\n[[listener]]\naddress = "0.0.0.0:8095"\n')
        with self.assertRaises(ConfigError):
            self.load('allow_private_listen = true\n[[listener]]\naddress = "8.8.8.8:8095"\n')
        for address in ("[::ffff:0.0.0.0]:8095", "[::ffff:8.8.8.8]:8095", "[::]:8095"):
            with self.assertRaises(ConfigError, msg=address):  # ::ffff:0.0.0.0 binds every IPv4 interface
                self.load(f'allow_private_listen = true\n[[listener]]\naddress = "{address}"\n')
        # A Tailscale address is allowed, and documented as serving the whole tailnet in the clear.
        cfg = self.load('allow_private_listen = true\n[[listener]]\naddress = "100.100.100.100:8095"\n'
                        'public_url = "https://box.example.test/"\n')
        self.assertEqual(cfg.listeners[0].host, "100.100.100.100")

    def test_public_url_must_be_https_unless_loopback(self):
        with self.assertRaisesRegex(ConfigError, "https"):
            self.load('[[listener]]\npublic_url = "http://term.example.test/"\n')
        cfg = self.load('[[listener]]\npublic_url = "https://term.example.test/remote"\n')
        self.assertEqual(cfg.listeners[0].public_url, "https://term.example.test/remote/")
        self.assertEqual(cfg.listeners[0].mount, "/remote")

    def test_proxy_header_without_a_secret_refuses_to_start(self):
        with self.assertRaisesRegex(ConfigError, "no secret"):
            self.load('[[listener]]\npublic_url = "https://t.example.test/"\nproxy_header = "X-Origin-Verify"\n')
        cfg = self.load('[[listener]]\npublic_url = "https://t.example.test/"\nproxy_header = "X-Origin-Verify"\n',
                        BON5AI_REMOTE_PROXY_SECRET="s3cret")
        self.assertEqual(cfg.proxy_secret, "s3cret")
        self.assertNotIn("s3cret", repr(cfg))  # never in logs or tracebacks

    def test_secret_file_must_be_private(self):
        secret = self.dir / "secret"
        secret.write_text("s3cret\n")
        os.chmod(secret, 0o644)
        text = (f'proxy_secret_file = "{secret}"\n[[listener]]\npublic_url = "https://t.example.test/"\n'
                'proxy_header = "X-Origin-Verify"\n')
        with self.assertRaisesRegex(ConfigError, "chmod 600"):
            self.load(text)
        os.chmod(secret, 0o600)
        self.assertEqual(self.load(text).proxy_secret, "s3cret")

    def test_unknown_settings_are_errors(self):
        with self.assertRaisesRegex(ConfigError, "unknown"):
            self.load('sesion = "typo"\n')
        with self.assertRaisesRegex(ConfigError, "unknown listener"):
            self.load('[[listener]]\nadress = "127.0.0.1:1"\n')

    def test_client_ip_header_needs_a_proxy_header(self):
        with self.assertRaisesRegex(ConfigError, "client_ip_header"):
            self.load('[[listener]]\nclient_ip_header = "CloudFront-Viewer-Address"\n')

    def test_host_checks_and_base_urls(self):
        cfg = self.load('[[listener]]\naddress = "127.0.0.1:8095"\npublic_url = "https://term.example.test/"\n'
                        'allowed_hosts = ["box.tailnet.test"]\n')
        listener = cfg.listeners[0]
        for host in ("term.example.test", "TERM.example.test", "127.0.0.1:8095", "localhost:8095",
                     "box.tailnet.test"):
            self.assertTrue(listener.host_allowed(host), host)
        for host in ("evil.test", "127.0.0.1:9999", "term.example.test.evil.test", ""):
            self.assertFalse(listener.host_allowed(host), host)
        self.assertEqual(listener.base_url("127.0.0.1:8095"), "http://127.0.0.1:8095/")
        self.assertEqual(listener.base_url("box.tailnet.test"), "https://term.example.test/")
        self.assertIn("https://term.example.test/mcp", listener.resources())
        self.assertIn("http://127.0.0.1:8095/mcp", listener.resources())

    def test_socket_paths_must_fit(self):
        with self.assertRaisesRegex(ConfigError, "too long"):
            load(env={**self.env, "XDG_RUNTIME_DIR": "/" + "d" * 120})
        cfg = load(env={**self.env, "XDG_RUNTIME_DIR": "/" + "d" * 120, "BON5AI_REMOTE_RUNTIME_DIR": "/run/x"})
        self.assertEqual(cfg.admin_socket, Path("/run/x/admin.sock"))

    def test_redirect_allowlist_must_be_https(self):
        with self.assertRaises(ConfigError):
            self.load('allowed_redirect_uris = ["http://example.test/cb"]\n')

    def test_private_dir_refuses_a_shared_one(self):
        path = self.dir / "rt"
        path.mkdir(mode=0o755)
        os.chmod(path, 0o755)
        with self.assertRaisesRegex(ConfigError, "0700"):
            ensure_private_dir(path)
        os.chmod(path, 0o700)
        self.assertEqual(ensure_private_dir(path), path)


if __name__ == "__main__":
    unittest.main()
