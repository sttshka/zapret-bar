#!/usr/bin/env python3
"""
Проверка «фейкового» TLS-приветствия на macOS — того же приёма, что у winws/nfqws.

Перед настоящим ClientHello в соединение подкладывается поддельный (SNI www.google.com),
который фильтр провайдера видит, а сервер — нет: у подделки малый TTL, сдвинутый номер
последовательности, неверная контрольная сумма или лишняя TCP-опция.

Пакеты отправляются через /dev/bpf прямо в Wi-Fi (en0), поэтому нужен root:
    sudo python3 scripts/fake-test.py
VPN выключать не нужно: и тестовые соединения, и подделки идут мимо туннеля.
"""
import fcntl, os, pwd, random, select, socket, ssl, struct, subprocess, sys, threading, time, json, urllib.request

IFACE = os.environ.get("IFACE", "en0")
HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_DIR = os.path.join(HERE, "..", "vendor", "zapret", "files", "fake")
TIMEOUT = 7

# --- ioctl'ы BPF (macOS, 64 бит) ---
BIOCSBLEN, BIOCGBLEN = 0xC0044266, 0x40044266
BIOCSETIF, BIOCIMMEDIATE = 0x8020426C, 0x80044270
BIOCSHDRCMPLT, BIOCSSEESENT = 0x80044275, 0x80044277
IP_BOUND_IF = 25


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def iface_info():
    ip = sh("ipconfig", "getifaddr", IFACE).strip()
    mac = next(l.split()[1] for l in sh("ifconfig", IFACE).splitlines() if l.strip().startswith("ether"))
    gw = next(l.split()[1] for l in sh("route", "-n", "get", "-ifscope", IFACE, "default").splitlines() if "gateway:" in l)
    gwmac = sh("arp", "-n", gw).split(" at ")[1].split()[0]
    norm = lambda m: bytes(int(x, 16) for x in m.split(":"))
    return ip, norm(mac), norm(gwmac)


def open_bpf():
    for i in range(256):
        try:
            fd = os.open(f"/dev/bpf{i}", os.O_RDWR)
            break
        except OSError:
            continue
    else:
        sys.exit("Нет свободного /dev/bpf (нужен sudo)")
    fcntl.ioctl(fd, BIOCSBLEN, struct.pack("I", 1 << 20))
    fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", IFACE.encode()))
    fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
    fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))
    fcntl.ioctl(fd, BIOCSSEESENT, struct.pack("I", 1))
    blen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, struct.pack("I", 0)))[0]
    return fd, blen


class Sniffer(threading.Thread):
    """Ловит SYN/SYN-ACK наших соединений, чтобы узнать номера последовательности."""

    def __init__(self, fd, blen):
        super().__init__(daemon=True)
        self.fd, self.blen = fd, blen
        self.flows = {}  # local_port -> dict
        self.lock = threading.Lock()

    def run(self):
        while True:
            r, _, _ = select.select([self.fd], [], [], 0.5)
            if not r:
                continue
            data = os.read(self.fd, self.blen)
            off = 0
            while off + 18 <= len(data):
                caplen, = struct.unpack_from("I", data, off + 8)
                hdrlen, = struct.unpack_from("H", data, off + 16)
                self.handle(data[off + hdrlen: off + hdrlen + caplen])
                off += (hdrlen + caplen + 3) & ~3

    def handle(self, pkt):
        if len(pkt) < 54 or pkt[12:14] != b"\x08\x00" or pkt[23] != 6:
            return
        ihl = (pkt[14] & 0x0F) * 4
        ttl = pkt[22]
        t = 14 + ihl
        sport, dport, seq, ack = struct.unpack_from("!HHII", pkt, t)
        flags = pkt[t + 13]
        with self.lock:
            if flags & 0x12 == 0x02 and sport in self.flows:          # наш SYN
                self.flows[sport]["isn_c"] = seq
            elif flags & 0x12 == 0x12 and dport in self.flows:        # SYN-ACK сервера
                self.flows[dport]["isn_s"] = seq
                self.flows[dport]["ttl"] = ttl

    def watch(self, port):
        with self.lock:
            self.flows[port] = {}

    def get(self, port):
        with self.lock:
            return dict(self.flows.get(port, {}))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_frame(src_mac, dst_mac, src, dst, sport, dport, seq, ack, payload, ttl=64, badsum=False, md5=False):
    opts = b""
    if md5:
        opts = b"\x13\x12" + bytes(16) + b"\x01\x01"  # MD5 signature (kind 19) + 2 NOP
    thl = 20 + len(opts)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (thl // 4) << 4, 0x18, 1024, 0, 0) + opts
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, thl + len(payload))
    c = csum(pseudo + tcp + payload)
    if badsum:
        c = (c + 1) & 0xFFFF or 1
    tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, random.randint(0, 0xFFFF), 0x4000, ttl, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp + payload


def resolve(host):
    try:
        with urllib.request.urlopen(f"https://dns.google/resolve?name={host}&type=A", timeout=5) as r:
            for a in json.load(r).get("Answer", []):
                if a.get("type") == 1:
                    return a["data"]
    except Exception:
        pass
    return socket.gethostbyname(host)


def attempt(env, host, ip, v):
    """Одно соединение: [фейки] + ClientHello (целиком или нарезкой) + GET, считаем байты ответа."""
    bpf, sniffer, src, mac, gwmac, fake = env
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(IFACE))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind((src, 0))
    port = s.getsockname()[1]
    sniffer.watch(port)
    s.settimeout(5)
    try:
        s.connect((ip, 443))
    except Exception as e:
        return f"нет TCP ({type(e).__name__})"
    t0 = time.time()
    while "isn_s" not in sniffer.get(port) and time.time() - t0 < 1:
        time.sleep(0.005)
    fl = sniffer.get(port)
    if "isn_s" not in fl or "isn_c" not in fl:
        s.close()
        return "не поймал SYN-ACK"
    seq, ack = fl["isn_c"] + 1, fl["isn_s"] + 1
    hops = max(1, 64 - fl["ttl"]) if fl["ttl"] <= 64 else max(1, 128 - fl["ttl"])
    HOPS[host] = hops

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    bin_, bout = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(bin_, bout, server_hostname=host)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = bout.read()

    if v.get("fake"):
        fseq, fack = seq, ack
        if v.get("badseq"):
            fseq, fack = seq - 10000, ack - 66000
        if v.get("randseq"):
            fseq, fack = random.getrandbits(32), random.getrandbits(32)
        if "abs_ttl" in v:
            ttl = v["abs_ttl"]
        elif "ttl_minus" in v:
            ttl = max(1, hops - v["ttl_minus"])
        else:
            ttl = 64
        frame = build_frame(mac, gwmac, src, ip, port, 443, fseq, fack, fake, ttl=ttl,
                            badsum=v.get("badsum", False), md5=v.get("md5", False))
        for _ in range(v.get("repeats", 6)):
            os.write(bpf, frame)
        time.sleep(0.003)

    if v.get("split"):
        i = hello.find(host.encode())
        sld = host.split(".")[-2]
        mid = i + host.rfind(sld) + len(sld) // 2 if i > 0 else 2
        cuts = [0, 1, mid, len(hello)]
        for a, b in zip(cuts, cuts[1:]):
            s.sendall(hello[a:b])
            time.sleep(0.002)
    else:
        s.sendall(hello)

    got = 0
    s.settimeout(1)
    deadline = time.time() + TIMEOUT
    sent_req = False
    try:
        while time.time() < deadline:
            try:
                if not sent_req:
                    tls.do_handshake()
                    tls.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
                    sent_req = True
                else:
                    while True:
                        d = tls.read(65536)
                        if not d:
                            return f"OK {got // 1024} КБ" if got else "пустой ответ"
                        got += len(d)
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLZeroReturnError:
                return f"OK {got // 1024} КБ" if got else "пустой ответ"
            out = bout.read()
            if out:
                s.sendall(out)
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return (f"OK {got // 1024} КБ" if got > 50000 else f"закрыто на {got // 1024} КБ") if sent_req else "сброс до TLS"
            bin_.write(chunk)
    except (ssl.SSLError, ConnectionError) as e:
        return f"ошибка {type(e).__name__}" + (f" на {got // 1024} КБ" if got else "")
    finally:
        s.close()
    if not sent_req:
        return "нет ответа на TLS (блок)"
    return f"OK {got // 1024} КБ (дольше {TIMEOUT}с)" if got > 150000 else f"ЗАМИРАЕТ на {got // 1024} КБ"


HOPS = {}

VARIANTS = [
    ("без фейка, целиком", {}),
    ("без фейка, нарезка", {"split": 1}),
    ("фейк TTL-1, целиком", {"fake": 1, "ttl_minus": 1}),
    ("фейк TTL-1, нарезка", {"fake": 1, "ttl_minus": 1, "split": 1}),
    ("фейк TTL-2, нарезка", {"fake": 1, "ttl_minus": 2, "split": 1}),
    ("фейк TTL-3, нарезка", {"fake": 1, "ttl_minus": 3, "split": 1}),
    ("фейк TTL=4, нарезка", {"fake": 1, "abs_ttl": 4, "split": 1}),
    ("фейк badseq, целиком", {"fake": 1, "badseq": 1}),
    ("фейк badseq, нарезка", {"fake": 1, "badseq": 1, "split": 1}),
    ("фейк badsum, целиком", {"fake": 1, "badsum": 1}),
    ("фейк badsum, нарезка", {"fake": 1, "badsum": 1, "split": 1}),
    ("фейк md5sig, нарезка", {"fake": 1, "md5": 1, "split": 1}),
    ("фейк случайный seq, нарезка", {"fake": 1, "randseq": 1, "split": 1}),
    ("фейк badseq+TTL-1, нарезка", {"fake": 1, "badseq": 1, "ttl_minus": 1, "split": 1}),
]


def main():
    if os.geteuid() != 0:
        sys.exit("Запустите через sudo: sudo python3 scripts/fake-test.py")
    src, mac, gwmac = iface_info()
    fake = open(os.path.join(FAKE_DIR, "tls_clienthello_www_google_com.bin"), "rb").read()
    bpf, blen = open_bpf()
    sniffer = Sniffer(bpf, blen)
    sniffer.start()
    env = (bpf, sniffer, src, mac, gwmac, fake)

    hosts = sys.argv[1:] or ["discord.com", "x.com"]
    ips = {h: resolve(h) for h in hosts}
    lines = [f"fake-test {time.strftime('%Y-%m-%d %H:%M')}  {IFACE}={src}  " + "  ".join(f"{h}={ips[h]}" for h in hosts)]
    print(lines[0], flush=True)
    for name, v in VARIANTS:
        row = f"{name:32}"
        for h in hosts:
            r = attempt(env, h, ips[h], dict(v))
            row += f" | {h}: {r:28}"
        print(row, flush=True)
        lines.append(row)
        time.sleep(1)

    lines.append(f"Хопов до серверов (по TTL ответа): {HOPS}")
    user = os.environ.get("SUDO_USER")
    home = pwd.getpwnam(user).pw_dir if user else os.path.expanduser("~")
    out_dir = os.path.join(home, "Library", "Application Support", "ZapretBar", "diagnostics")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"fake-test-{time.strftime('%Y%m%d-%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    if user:
        pw = pwd.getpwnam(user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    print(f"\n{lines[-1]}")
    print(f"Готово. Отчёт: {path}")


if __name__ == "__main__":
    main()
