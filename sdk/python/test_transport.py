import threading
import unittest
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock
from urllib.error import HTTPError

from galleton import Galleton, GalletonError


class TransportTests(unittest.TestCase):
    def test_body_failures_are_typed_and_not_retried(self):
        for failure in [IncompleteRead(b"partial", 20), TimeoutError(), OSError()]:
            with self.subTest(error=type(failure).__name__):
                response = MagicMock()
                response.code = 200
                response.read.side_effect = failure
                client = Galleton("local")
                client._opener = MagicMock()
                client._opener.open.return_value = response
                with self.assertRaises(GalletonError) as caught:
                    client.status("alice")
                self.assertEqual(caught.exception.code, "daemon_unavailable")
                self.assertEqual(caught.exception.status, 200)
                self.assertIn("may already have completed", str(caught.exception))
                client._opener.open.assert_called_once()
                response.__exit__.assert_called_once()

    def test_http_error_body_failure_is_typed(self):
        body = MagicMock()
        body.closed = False
        body.read.side_effect = IncompleteRead(b"partial", 20)
        client = Galleton("local")
        client._opener = MagicMock()
        client._opener.open.side_effect = HTTPError(
            "http://127.0.0.1:8766/v1/sessions/alice", 503,
            "Service Unavailable", {}, body,
        )
        with self.assertRaises(GalletonError) as caught:
            client.status("alice")
        self.assertEqual(caught.exception.code, "daemon_unavailable")
        self.assertEqual(caught.exception.status, 503)
        client._opener.open.assert_called_once()
        body.close.assert_called_once()

    def test_open_protocol_failure_is_typed(self):
        client = Galleton("local")
        client._opener = MagicMock()
        client._opener.open.side_effect = IncompleteRead(b"", 20)
        with self.assertRaises(GalletonError) as caught:
            client.status("alice")
        self.assertEqual(caught.exception.code, "daemon_unavailable")
        client._opener.open.assert_called_once()

    def test_complete_http_error_preserves_daemon_error(self):
        body = MagicMock()
        body.closed = False
        body.read.return_value = b'{"error":{"code":"retry_later","message":"Try later."}}'
        client = Galleton("local")
        client._opener = MagicMock()
        client._opener.open.side_effect = HTTPError(
            "http://127.0.0.1:8766/v1/sessions/alice", 503,
            "Service Unavailable", {}, body,
        )
        with self.assertRaises(GalletonError) as caught:
            client.status("alice")
        self.assertEqual(caught.exception.code, "retry_later")
        self.assertEqual(caught.exception.status, 503)
        body.close.assert_called_once()

    def test_truncated_chunked_response_from_loopback_server(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                # Advertise a chunk longer than the bytes actually delivered.
                self.wfile.write(b'20\r\n{"id":"alice"}')
                self.wfile.flush()
                self.close_connection = True

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            client = Galleton("local", f"http://127.0.0.1:{server.server_port}", timeout=2)
            with self.assertRaises(GalletonError) as caught:
                client.status("alice")
            self.assertEqual(caught.exception.code, "daemon_unavailable")
            self.assertEqual(caught.exception.status, 200)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
