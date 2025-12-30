from tls_hijack.ssl_client import DisconnectionReason, SslClient
from tls_hijack.ssl_proxy_callback import SslProxyCallback
from tls_hijack.ssl_server import SslServer


class LoggingProxyCallback(SslProxyCallback):

    def __init__(self, client_fd: int, host: str, port: int):
        """
        proxy: 可选，把 SslProxy 实例传进来，这样可以在 callback 里主动发给 client。
               如果你不想在这里发消息，可以不传。
        """
        super().__init__(client_fd, host, port)
        self.total_bytes_sent = 0
        self.total_bytes_recv = 0

    def on_connect(self, server: SslServer, target_client: SslClient):
        self.server = server
        self.target_client = target_client
        print(f"[CB] client_fd={self.client_fd} connected from {self.host}:{self.port}")

    def on_send_message(self, data: bytearray) -> bytearray:
        """
        来自本地客户端 -> 代理
        """
        self.total_bytes_sent += len(data)
        print(f"[CB] from client_fd={self.client_fd} -> proxy: {data!r}")
        return data

    def on_recv_message(self, data: bytearray) -> bytearray:
        """
        来自目标服务器 -> 代理 -> 客户端
        """
        self.total_bytes_recv += len(data)
        print(f"[CB] from target -> client_fd={self.client_fd}: {data!r}")
        return data

    def on_disconnect(self, reason: DisconnectionReason):
        print(f"[CB] client_fd={self.client_fd} disconnected from {self.host}:{self.port} "
              f"reason={reason} "
              f"total_bytes_sent={self.total_bytes_sent} "
              f"total_bytes_recv={self.total_bytes_recv}")


callbacks = [LoggingProxyCallback]