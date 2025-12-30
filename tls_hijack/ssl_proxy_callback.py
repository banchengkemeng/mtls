from tls_hijack.ssl_client import DisconnectionReason, SslClient
from tls_hijack.ssl_server import SslServer


class SslProxyCallback:
    def __init__(self, client_fd: int, host: str, port: int):
        self.client_fd = client_fd
        self.host = host
        self.port = port

    def on_connect(self, server : SslServer, target_client: SslClient):
        raise NotImplementedError

    def on_send_message(self, data: bytearray) -> bytearray:
        raise NotImplementedError

    def on_recv_message(self, data: bytearray) -> bytearray:
        raise NotImplementedError

    def on_disconnect(self, reason: DisconnectionReason):
        raise NotImplementedError
