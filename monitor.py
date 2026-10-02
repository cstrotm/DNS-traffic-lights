#!/usr/bin/env python3
"""DNS domain traffic light monitor with Sixel terminal display.

Requires a Sixel-capable terminal (e.g. xterm -ti vt340, mlterm, foot,
iTerm2, or WezTerm).

Usage:
    python monitor.py [config.yaml]
"""

import fcntl
import math
import os
import select
import signal
import struct
import sys
import termios
import time
import tty
import concurrent.futures

import yaml
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from PIL import Image, ImageDraw, ImageFont

# ── layout constants ────────────────────────────────────────────────────────
LIGHT_W   = 76    # traffic-light widget width  (px)  — three lights side by side
LIGHT_H   = 28    # traffic-light widget height (px)
ROW_H     = 52    # height per domain row       (px)
HEADER_H  = 52    # header section height       (px)
PAD       = 12    # outer padding               (px)
GAP       = 14    # gap between light and text  (px)
FONT_SIZE = 17
SMALL_SIZE = 13

# ── DNS status colours ───────────────────────────────────────────────────────
STATUS_RGB = {
    'green':  (70,  230,  70),
    'yellow': (230, 230,  70),
    'red':    (230,  70,  70),
}


# ── terminal geometry ─────────────────────────────────────────────────────────

_resize_flag = False


def _handle_sigwinch(sig, frame):
    global _resize_flag
    _resize_flag = True


def _terminal_info():
    """Return (cols_ch, rows_ch, cols_px, rows_px) or None."""
    try:
        buf = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b'\x00' * 8)
        rows_ch, cols_ch, cols_px, rows_px = struct.unpack('HHHH', buf)
        if cols_ch > 0 and rows_ch > 0 and cols_px > 0 and rows_px > 0:
            return cols_ch, rows_ch, cols_px, rows_px
    except Exception:
        pass
    try:
        ts = os.get_terminal_size()
        return ts.columns, ts.lines, 0, 0
    except Exception:
        return None


def _center_pos(img_w: int, img_h: int) -> tuple[int, int, int]:
    """Return (col, row, img_rows_in_cells) — 1-based cursor position to center img."""
    info = _terminal_info()
    if info is None:
        return 1, 1, math.ceil(img_h / 16)

    cols_ch, rows_ch, cols_px, rows_px = info
    cell_w = (cols_px / cols_ch) if cols_px > 0 else 8.0
    cell_h = (rows_px / rows_ch) if rows_px > 0 else 16.0

    img_rows = math.ceil(img_h / cell_h)
    col = max(1, int((cols_ch - img_w / cell_w) / 2) + 1)
    row = max(1, int((rows_ch - img_rows) / 2) + 1)
    return col, row, img_rows


# ── config ───────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


# ── DNS queries ───────────────────────────────────────────────────────────────

# (name, IPv4 addresses, IPv6 addresses, SOA serial or None, SOA round-trip
#  time in ms or None, error label or None)
NsInfo = tuple[str, list[str], list[str], int | None, float | None, str | None]
Result = tuple[str, str, list[NsInfo]]


def _addresses(resolver: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        return sorted(r.address for r in resolver.resolve(name, rtype))
    except Exception:
        return []


def _soa_serial(
    zone: str, addrs: list[str]
) -> tuple[int | None, float | None, str | None]:
    """Ask each address directly for the zone's SOA.

    Return (serial, round-trip time in ms of the answering query, error).
    """
    if not addrs:
        return None, None, 'NO ADDRESS'
    err = 'TIMEOUT'
    for addr in addrs:
        query = dns.message.make_query(zone, 'SOA')
        query.flags &= ~dns.flags.RD          # ask the server itself, not a cache
        start = time.monotonic()
        try:
            resp = dns.query.udp(query, addr, timeout=3.0)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(query, addr, timeout=3.0)
        except Exception:
            continue
        rtt_ms = (time.monotonic() - start) * 1000
        if resp.rcode() != dns.rcode.NOERROR:
            err = dns.rcode.to_text(resp.rcode())
            continue
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                return rrset[0].serial, rtt_ms, None
        err = 'NO SOA'
    return None, None, err


def check_domain(domain: str) -> Result:
    """Return (traffic-light colour, rcode label, per-nameserver info).

    The status comes from the NS query for the zone; each name server found
    is then asked directly for the zone's SOA record.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(domain, 'NS')
    except dns.resolver.NXDOMAIN:
        return 'yellow', 'NXDOMAIN', []
    except dns.resolver.NoAnswer:
        # NOERROR but no NS at this name (e.g. not a zone apex) — domain exists
        return 'green', 'NOERROR', []
    except dns.resolver.NoNameservers:
        return 'red', 'SERVFAIL', []
    except dns.exception.Timeout:
        return 'red', 'TIMEOUT', []
    except Exception as exc:
        return 'red', type(exc).__name__.upper()[:12], []

    names = sorted(str(r.target).rstrip('.') for r in answer)

    def collect(name: str) -> NsInfo:
        v4 = _addresses(resolver, name, 'A')
        v6 = _addresses(resolver, name, 'AAAA')
        serial, rtt_ms, err = _soa_serial(domain, v4 + v6)
        return name, v4, v6, serial, rtt_ms, err

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(names), 16)) as pool:
        return 'green', 'NOERROR', list(pool.map(collect, names))


def query_all(domains: list[str]) -> list[Result]:
    """Query all domains concurrently; preserve input order."""
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(domains), 32)
    ) as pool:
        futs = {pool.submit(check_domain, d): d for d in domains}
        out: dict[str, Result] = {}
        for fut in concurrent.futures.as_completed(futs):
            d = futs[fut]
            try:
                out[d] = fut.result()
            except Exception:
                out[d] = ('red', 'ERROR', [])
    return [out[d] for d in domains]


# ── image construction ────────────────────────────────────────────────────────

def _load_font(size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        '/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/TTF/DejaVuSans.ttf',
        '/usr/share/fonts/liberation-sans-fonts/LiberationSans-Regular.ttf',
        '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except (IOError, OSError):
            pass
    try:
        return ImageFont.load_default(size=size)   # Pillow ≥ 10.1
    except TypeError:
        return ImageFont.load_default()


def _draw_traffic_light(draw: ImageDraw.ImageDraw, x: int, y: int, status: str) -> None:
    draw.rounded_rectangle(
        [x, y, x + LIGHT_W, y + LIGHT_H], radius=4,
        fill=(50, 50, 55), outline=(85, 85, 90),
    )
    cy = y + LIGHT_H // 2
    r  = LIGHT_H // 2 - 4
    for name, dim, bright, frac in (
        ('red',    (100,  15,  15), (255,  55,  55), 1 / 6),
        ('yellow', (100, 100,  15), (255, 255,  55), 1 / 2),
        ('green',  ( 15, 100,  15), ( 55, 255,  55), 5 / 6),
    ):
        cx = x + int(LIGHT_W * frac)
        draw.ellipse(
            [cx - r, cy - r, cx + r, cy + r],
            fill=(bright if status == name else dim),
        )


NS_LINE_H = SMALL_SIZE + 4
NS_COL_GAP = 18


def _text_w(font: ImageFont.FreeTypeFont, text: str) -> int:
    try:
        return int(font.getlength(text))
    except AttributeError:
        return len(text) * int(SMALL_SIZE * 0.65)


NS_COLS = 5   # name, IPv4, IPv6, serial, round-trip time


def _ns_columns(ns: list[NsInfo]) -> list[tuple[list[str], str | None]]:
    """Text columns (name, IPv4, IPv6, serial, RTT) per nameserver, plus error."""
    return [
        ([name, ', '.join(v4) or '-', ', '.join(v6) or '-',
          '-' if serial is None else f'serial {serial}',
          '' if rtt_ms is None else f'{rtt_ms:.1f} ms'], err)
        for name, v4, v6, serial, rtt_ms, err in ns
    ]


def _row_height(ns: list[NsInfo]) -> int:
    body = FONT_SIZE + 4 + SMALL_SIZE + 4 + len(ns) * NS_LINE_H
    return max(ROW_H, body + 16)


def build_image(
    domains: list[str],
    results: list[Result],
    font: ImageFont.FreeTypeFont,
    small_font: ImageFont.FreeTypeFont,
) -> Image.Image:
    # Column widths for the nameserver table, shared by all domains.
    col_w = [0] * NS_COLS
    for _, _, ns in results:
        for cols, _err in _ns_columns(ns):
            for k in range(NS_COLS):
                col_w[k] = max(col_w[k], _text_w(small_font, cols[k]))
    table_w = sum(col_w) + (NS_COLS - 1) * NS_COL_GAP

    longest = max(domains, key=len, default='')
    text_w = max(_text_w(font, longest) + 90, table_w)

    heights = [_row_height(ns) for _, _, ns in results]
    img_w = PAD + LIGHT_W + GAP + text_w + PAD
    img_h = HEADER_H + sum(heights) + PAD

    img  = Image.new('RGB', (img_w, img_h), (22, 22, 30))
    draw = ImageDraw.Draw(img)

    # Header
    draw.text((PAD, 8),
              'DNS Traffic Light Monitor',
              fill=(200, 200, 220), font=font)
    draw.text((PAD, 8 + FONT_SIZE + 3),
              f'Updated: {time.strftime("%Y-%m-%d  %H:%M:%S")}',
              fill=(110, 110, 130), font=small_font)

    ry = HEADER_H
    for domain, (status, rcode, ns), rh in zip(domains, results, heights):
        _draw_traffic_light(draw, PAD, ry + 8, status)

        tx = PAD + LIGHT_W + GAP
        ty = ry + 8
        color = STATUS_RGB.get(status, (180, 180, 180))

        draw.text((tx, ty), domain, fill=(210, 210, 225), font=font)
        ty += FONT_SIZE + 4
        draw.text((tx, ty), rcode, fill=color, font=small_font)
        ty += SMALL_SIZE + 4

        # Serials that differ between name servers are all shown in red.
        mismatch = len({n[3] for n in ns if n[3] is not None}) > 1

        for cols, err in _ns_columns(ns):
            x = tx
            for k in range(NS_COLS):
                fill = (150, 150, 170)
                text = cols[k]
                if k == 3 and (err or mismatch):
                    fill = STATUS_RGB['red']
                    text = err or text
                draw.text((x, ty), text, fill=fill, font=small_font)
                x += col_w[k] + NS_COL_GAP
            ty += NS_LINE_H
        ry += rh

    return img


# ── Sixel encoder ─────────────────────────────────────────────────────────────
#
# Each Sixel "band" covers 6 pixel rows.  For every band we iterate over the
# colours that actually appear in it; for each such colour we output one sixel
# character per column (63 + 6-bit mask: bit N = row band_start+N belongs to
# this colour).  Colours within a band are separated by '$' (CR) so they
# overlay each other.  Bands are separated by '-' (LF+CR).  RLE ('!n<c>')
# compresses runs of identical characters.

def _rle_encode(chars: list[str]) -> str:
    parts: list[str] = []
    i = 0
    while i < len(chars):
        c   = chars[i]
        run = 1
        while i + run < len(chars) and chars[i + run] == c:
            run += 1
        parts.append(f'!{run}{c}' if run > 3 else c * run)
        i += run
    return ''.join(parts)


def image_to_sixel(img: Image.Image) -> str:
    # Quantise to 128 colours (no dithering — cleaner for solid shapes).
    q   = img.quantize(colors=128, dither=0)
    pal = q.getpalette()          # [R0,G0,B0, R1,G1,B1, …]  (768 values)
    W, H = q.size
    pix = list(q.get_flattened_data())  # flat list of palette indices, row-major

    out: list[str] = []
    out.append('\033Pq')                  # DCS + sixel mode
    out.append(f'"1;1;{W};{H}')          # raster attributes (1:1 aspect, WxH px)

    used = sorted(set(pix))
    for idx in used:
        r = pal[idx * 3]     * 100 // 255
        g = pal[idx * 3 + 1] * 100 // 255
        b = pal[idx * 3 + 2] * 100 // 255
        out.append(f'#{idx};2;{r};{g};{b}')   # colour definition

    for band in range(0, H, 6):
        rows  = min(6, H - band)
        first = True

        for c in used:
            chars: list[str] = []
            any_set = False
            for x in range(W):
                bits = 0
                for bit in range(rows):
                    if pix[(band + bit) * W + x] == c:
                        bits   |= 1 << bit
                        any_set = True
                chars.append(chr(63 + bits))

            if not any_set:
                continue

            if not first:
                out.append('$')           # CR — return to start of band
            first = False
            out.append(f'#{c}')
            out.append(_rle_encode(chars))

        out.append('-')                   # LF — advance to next band

    out.append('\033\\')                  # ST — string terminator
    return ''.join(out)


# ── main loop ─────────────────────────────────────────────────────────────────

def _wait_or_quit(seconds: float, on_tick=None) -> str:
    """Wait up to *seconds*; return 'quit', 'resize', or 'timeout'.

    *on_tick(secs_left)* is called each time the integer second count changes.
    """
    global _resize_flag
    deadline   = time.monotonic() + seconds
    last_shown = None
    while True:
        if _resize_flag:
            _resize_flag = False
            return 'resize'
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 'timeout'
        secs = int(remaining)
        if secs != last_shown:
            if on_tick:
                on_tick(secs)
            last_shown = secs
        try:
            ready, _, _ = select.select([sys.stdin], [], [], min(remaining, 0.1))
        except (InterruptedError, OSError):
            continue
        if ready:
            ch = sys.stdin.read(1)
            if ch in ('q', 'Q', '\x1b'):   # q, Q, or ESC
                return 'quit'


def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else 'config.yaml'
    try:
        cfg = load_config(config_path)
    except FileNotFoundError:
        sys.exit(f'Error: {config_path!r} not found.')
    except yaml.YAMLError as exc:
        sys.exit(f'Error parsing {config_path!r}: {exc}')

    domains = cfg.get('domains', [])
    if not domains:
        sys.exit('Error: no domains listed under "domains:" in config.yaml')

    interval = int(cfg.get('interval', 30))

    font       = _load_font(FONT_SIZE)
    small_font = _load_font(SMALL_SIZE)

    signal.signal(signal.SIGWINCH, _handle_sigwinch)

    # Switch stdin to raw (single-keypress) mode so we don't need Enter.
    old_attrs = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    sys.stdout.write('\033[?25l')   # hide cursor
    sys.stdout.flush()

    results = None

    try:
        while True:
            if results is None:
                results = query_all(domains)
            img   = build_image(domains, results, font, small_font)
            sixel = image_to_sixel(img)

            col, row, img_rows = _center_pos(img.width, img.height)
            countdown_row = row + img_rows + 1

            sys.stdout.write('\033[2J')             # clear screen
            sys.stdout.write(f'\033[{row};{col}H')  # move to centered position
            sys.stdout.write(sixel)
            sys.stdout.flush()

            def show_countdown(secs: int, _cr=countdown_row) -> None:
                sys.stdout.write(
                    f'\033[{_cr};1H\033[K  Next refresh in {secs:3d}s  '
                    f'\033[2m(q / Esc to quit)\033[0m'
                )
                sys.stdout.flush()

            action = _wait_or_quit(interval, on_tick=show_countdown)
            if action == 'quit':
                break
            elif action == 'resize':
                pass        # redraw with cached results; skip DNS re-query
            else:           # timeout
                results = None
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_attrs)
        sys.stdout.write('\033[?25h\r\n')   # restore cursor
        sys.stdout.flush()
        print('Stopped.')


if __name__ == '__main__':
    main()
