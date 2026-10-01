import unittest
from galleton import Galleton, Response


class ClientTests(unittest.TestCase):
    def test_remote_daemon_rejected(self):
        for url in ["https://example.com", "http://localhost:8766", "http://u:p@127.0.0.1:8766", "http://127.0.0.1/a"]:
            with self.assertRaises(ValueError):
                Galleton("local", url)

    def test_loopback_accepted(self):
        Galleton("local")
        Galleton("local", "http://[::1]:8766")

    def test_bad_id_rejected(self):
        with self.assertRaises(ValueError):
            Galleton("local").status("../other")

    def test_response(self):
        response = Response(200, {}, b'{"ok":true}', 1)
        self.assertTrue(response.ok)
        self.assertEqual(response.json(), {"ok": True})

    def test_header_injection_rejected(self):
        with self.assertRaises(ValueError):
            Galleton("bad\r\ninjection")


if __name__ == "__main__":
    unittest.main()
