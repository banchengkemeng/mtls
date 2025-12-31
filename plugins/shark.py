import time
import threading
import queue
import warnings
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Callable, Tuple

from scapy.all import Ether, IP, TCP
import pyshark

from tls_hijack.ssl_client import DisconnectionReason, SslClient
from tls_hijack.ssl_proxy_callback import SslProxyCallback
from tls_hijack.ssl_server import SslServer

from textual.app import App, ComposeResult
from textual.widgets import DataTable, Static, Header, Footer
from textual.screen import Screen
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax

warnings.filterwarnings("ignore", category=UserWarning, module='pyshark')

# ======================= 1. 数据模型 =======================

@dataclass
class ProtocolEvent:
    global_id: int       # 全局唯一包 ID
    conn_id: int         # 连接句柄 ID
    protocol: str
    ts: float
    duration: float
    direction: str       # "SENT" 或 "RECV"
    summary: str
    detail: str

EVENT_QUEUE: "queue.Queue[ProtocolEvent]" = queue.Queue()
# 核心：通过 global_id 精确查找历史包
GLOBAL_EVENT_MAP: Dict[int, ProtocolEvent] = {}
GLOBAL_COUNTER = 0
COUNTER_LOCK = threading.Lock()

# ======================= 2. 协议分发处理器 =======================

class ProtocolDispatcher:
    def __init__(self):
        # 协议摘要提取映射
        self.handler_map: Dict[str, Callable[[Any], str]] = {
            'HTTP':      self._handle_http,
            'MYSQL':     self._handle_mysql,
            'REDIS':     self._handle_redis,
            'MQTT':      self._handle_mqtt,
            'DNS':       self._handle_dns,
            'HTTP2':     self._handle_http2,
            'JSON':      lambda p: f"JSON: {str(p.json.value)[:60]}...",
        }
        # 协议颜色映射
        self.proto_styles = {
            "HTTP": "bold green", "MYSQL": "bold cyan", "REDIS": "bold orange3",
            "DNS": "bold magenta", "JSON": "bold yellow", "DEFAULT": "bold white"
        }
        # 方向渲染配置
        self.dir_config = {
            "SENT": {"icon": " ➔  ", "style": "bright_blue", "label": "C->S"},
            "RECV": {"icon": " ⬅  ", "style": "bright_red", "label": "S->C"}
        }
        # 语法高亮映射 (修复属性缺失问题)
        self.lexer_map = {
            "HTTP": "http", 
            "MYSQL": "sql", 
            "JSON": "json", 
            "HTTP2": "http"
        }

    def get_info(self, pkt, layers: List[str]) -> Tuple[str, str]:
        summary, proto_name = "TCP Data", pkt.highest_layer
        for name in self.handler_map:
            if name in layers:
                try:
                    summary = self.handler_map[name](pkt)
                    proto_name = name
                    break
                except: continue
        return proto_name, summary

    def get_proto_render(self, protocol: str) -> Text:
        return Text(protocol, style=self.proto_styles.get(protocol, self.proto_styles["DEFAULT"]))

    def get_dir_render(self, direction_tag: str) -> Text:
        cfg = self.dir_config.get(direction_tag, self.dir_config["SENT"])
        return Text(f"{cfg['icon']} {cfg['label']}", style=cfg["style"])

    def get_latency_render(self, duration: float) -> Text:
        if duration <= 0: return Text("-", style="dim")
        text = f"{duration*1000:.0f}ms" if duration < 1 else f"{duration:.2f}s"
        style = "green" if duration < 0.2 else "yellow" if duration < 0.8 else "red"
        return Text(text, style=style)

    def get_lexer(self, protocol: str) -> str:
        return self.lexer_map.get(protocol, "text")

    # --- 摘要提取实现 ---
    def _handle_http(self, pkt):
        h = pkt.http
        return getattr(h, 'request_line', None) or getattr(h, 'response_line', None) or "HTTP Data"

    def _handle_mysql(self, pkt):
        return f"SQL: {getattr(pkt.mysql, 'query', 'Cmd/Auth')}"

    def _handle_redis(self, pkt):
        return str(pkt.redis).replace('\\n', ' ').strip()[:80]

    def _handle_mqtt(self, pkt):
        return f"MQTT {getattr(pkt.mqtt, 'msgtype', '')} Topic: {getattr(pkt.mqtt, 'topic', 'N/A')}"

    def _handle_dns(self, pkt):
        return f"DNS Query: {getattr(pkt.dns, 'qry_name', 'N/A')}"

    def _handle_http2(self, pkt):
        return f"H2 Stream: {getattr(pkt.http2, 'streamid', 'N/A')}"

DISPATCHER = ProtocolDispatcher()

# ======================= 3. 核心分析引擎 =======================

class PySharkTuiPlugin(SslProxyCallback):
    def __init__(self, client_fd: int, host: str, port: int):
        super().__init__(client_fd, host, port)
        self.data_queue = queue.Queue(maxsize=2000)
        self.running = True
        self.client_port, self.server_port = 12345, (port if port else 80)
        self.client_seq, self.server_seq = 1001, 2001
        self.last_request_ts: Optional[float] = None
        self.analysis_thread = threading.Thread(target=self._worker, daemon=True)
        self.analysis_thread.start()

    def _worker(self):
        capture = pyshark.InMemCapture(linktype=1)
        while True:
            try:
                item = self.data_queue.get(timeout=1 if self.running else 0.1)
                if item is None: break
                raw_data, tag = item
                now = time.time()
                if tag == "RAW":
                    capture.parse_packet(raw_data)
                else:
                    is_sent = (tag == "SENT")
                    if is_sent: self.last_request_ts = now
                    duration = (now - self.last_request_ts) if (not is_sent and self.last_request_ts) else 0.0
                    
                    pkt_obj = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/ \
                              TCP(sport=(self.client_port if is_sent else self.server_port), 
                                  dport=(self.server_port if is_sent else self.client_port),
                                  flags="PA", seq=(self.client_seq if is_sent else self.server_seq), 
                                  ack=(self.server_seq if is_sent else self.client_seq)) / bytes(raw_data)
                    
                    if is_sent: self.client_seq += len(raw_data)
                    else: self.server_seq += len(raw_data)
                    
                    packet = capture.parse_packet(bytes(pkt_obj))
                    if packet: self._process_packet(packet, tag, now, duration)
                
                if len(capture) > 15: capture.clear()
            except Exception: pass
        capture.close()

    def _process_packet(self, pkt, tag, ts, duration):
        global GLOBAL_COUNTER
        layers = [l.layer_name.upper() for l in pkt.layers]
        proto_name, summary = DISPATCHER.get_info(pkt, layers)
        
        ignored = {'ETH', 'IP', 'SLL', 'TCP'} if proto_name != 'TCP' else {'ETH', 'IP', 'SLL'}
        detail_list = []
        for l in pkt.layers:
            lname = l.layer_name.upper()
            if lname in ignored: continue
            content = f"LAYER: {lname}\n"
            if lname == 'DATA' and hasattr(l, 'data'):
                raw_hex = l.data.replace(':', '')
                try:
                    printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes.fromhex(raw_hex)])
                    content += f"Hex: {raw_hex}\nText: {printable}"
                except: content += f"Hex: {raw_hex}"
            else:
                try:
                    for field in l.field_names: content += f"  {field}: {getattr(l, field)}\n"
                except: content += str(l)
            detail_list.append(content)

        with COUNTER_LOCK:
            GLOBAL_COUNTER += 1
            current_id = GLOBAL_COUNTER

        event = ProtocolEvent(
            global_id=current_id, conn_id=self.client_fd, protocol=proto_name, 
            ts=ts, duration=duration, direction=tag, summary=summary, 
            detail="\n\n".join(detail_list)
        )
        
        GLOBAL_EVENT_MAP[current_id] = event
        EVENT_QUEUE.put(event)

    def on_send_message(self, data): self.data_queue.put((bytearray(data), "SENT")); return data
    def on_recv_message(self, data): self.data_queue.put((bytearray(data), "RECV")); return data
    def on_disconnect(self, reason): self.running = False; self.data_queue.put(None)
    def on_connect(self, server, client):
        for p in [TCP(flags="S", seq=1000), TCP(flags="SA", seq=2000, ack=1001), TCP(flags="A", seq=1001, ack=2001)]:
            pkt = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/p
            self.data_queue.put((bytes(pkt), "RAW"))

# ======================= 4. TUI 呈现层 =======================

class DetailScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]
    
    def __init__(self, event_id: int, **kwargs):
        super().__init__(**kwargs)
        self.event_id = event_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="detail_container")
        yield Footer()

    def on_mount(self) -> None:
        # 使用全局映射找到当时那一行的精确包
        ev = GLOBAL_EVENT_MAP.get(self.event_id)
        if not ev:
            self.query_one("#detail_container").update("Packet data has been cleared or not found.")
            return

        lexer = DISPATCHER.get_lexer(ev.protocol)
        syntax = Syntax(ev.detail, lexer, theme="monokai", word_wrap=True)
        
        self.query_one("#detail_container").update(
            Panel(syntax, title=f" {ev.protocol} Packet Detail [ID:{ev.global_id}] ", border_style="bright_blue")
        )

class AnalyzerTuiApp(App):
    TITLE = "PyShark Master Auditor"
    CSS = """
    DataTable { height: 1fr; border: thick $primary; margin: 1 2; background: $surface; }
    #detail_container { padding: 1 2; height: 1fr; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("i", "open_detail", "Inspect"), ("c", "clear", "Clear")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        self.table = DataTable(zebra_stripes=True, cursor_type="row")
        # 第一列隐藏存放 global_id
        self.table.add_columns("ID", "Conn", "Time", "Proto", "Direction", "Latency", "Summary")
        yield self.table
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.1, self._update_table)

    def _update_table(self) -> None:
        while True:
            try:
                ev = EVENT_QUEUE.get_nowait()
                time_str = datetime.fromtimestamp(ev.ts).strftime("%H:%M:%S")
                
                self.table.add_row(
                    str(ev.global_id), 
                    str(ev.conn_id),
                    time_str,
                    DISPATCHER.get_proto_render(ev.protocol),
                    DISPATCHER.get_dir_render(ev.direction),
                    DISPATCHER.get_latency_render(ev.duration),
                    ev.summary
                )
                if self.table.row_count > 0:
                    self.table.scroll_to(y=self.table.row_count)
            except (queue.Empty, ValueError): break

    def action_clear(self) -> None: 
        self.table.clear()
        GLOBAL_EVENT_MAP.clear()

    async def action_open_detail(self) -> None:
        if self.table.cursor_row is not None:
            try:
                # 获取选中行的 RowKey
                row_key = list(self.table.rows.keys())[self.table.cursor_row]
                row_data = self.table.get_row(row_key)
                # 提取当时存入的第一列 global_id
                event_id = int(str(row_data[0]))
                await self.push_screen(DetailScreen(event_id))
            except Exception: pass

def start_tui():
    AnalyzerTuiApp().run()

callbacks = [PySharkTuiPlugin]
init_cb = start_tui