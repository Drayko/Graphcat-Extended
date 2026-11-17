#!/usr/bin/env python3

import argparse
from collections import Counter
import calendar
import time
import os
import re
import string
import sys
from typing import Dict, List, Optional, Tuple
import tempfile
import shutil
import difflib
import urllib.request
import urllib.error
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from fpdf import FPDF
from fpdf.enums import Align
from fpdf.fonts import FontFace
from tqdm import tqdm
from zxcvbn import zxcvbn

# --- Color palettes ---
COLORS_QUALITATIVE = plt.cm.Set2.colors
COLORS_SEQUENTIAL = plt.cm.viridis.colors

ACCENT = (53, 99, 236)      # #3563EC
INK = (33, 33, 33)
MUTED = (110, 110, 110)

KEYBOARD_WALKS_URL = (
    'https://raw.githubusercontent.com/danielmiessler/SecLists/master/'
    'Passwords/Keyboard-Walks/Keyboard-Combinations.txt'
)


# --- PDF engine detection -------------------------------------------------
# WeasyPrint renders HTML/CSS but is not pure Python: it binds to Pango, Cairo
# and GDK-PixBuf through cffi, and blows up at import time when those system
# libraries are missing. fpdf2 is a pure-Python wheel with no system
# dependencies at all, so it is the fallback that always works.

def weasyprint_status() -> Tuple[bool, str]:
    """Returns (available, reason). Never raises."""
    try:
        import weasyprint  # noqa: F401
        import jinja2  # noqa: F401
        return True, ''
    except ImportError as exc:
        return False, f'not installed ({exc})'
    except OSError as exc:
        return False, f'missing system libraries ({exc})'
    except Exception as exc:  # pragma: no cover - defensive
        return False, f'unusable ({exc})'


SYSTEM_LIB_HINT = """\
[!] WeasyPrint is installed but cannot load its system libraries.
[!] Reason: {reason}
[!]
[!] WeasyPrint needs Pango, Cairo and GDK-PixBuf, which pip cannot install.
[!]   Debian/Ubuntu/Kali : sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 \\
[!]                          libharfbuzz0b libcairo2 libgdk-pixbuf-2.0-0 libffi-dev
[!]   Fedora/RHEL        : sudo dnf install -y pango cairo gdk-pixbuf2 libffi-devel
[!]   Arch               : sudo pacman -S pango cairo gdk-pixbuf2 libffi
[!]   macOS              : brew install pango cairo gdk-pixbuf libffi
[!]
[!] Or just drop the flag: the default engine (-pdf-engine fpdf) is pure Python
[!] and needs none of the above."""


# --- Potfile values --------------------------------------------------------

HEX_ENTRY_RE = re.compile(r'^\$HEX\[([0-9a-fA-F]*)\]$')


def decode_potfile_value(value: str) -> Tuple[str, bool]:
    """Unwraps hashcat's $HEX[...] notation into the real password.

    hashcat falls back to $HEX[...] whenever a password would otherwise break
    the potfile format: it contains a colon, a newline, or bytes that are not
    valid UTF-8. Leaving it wrapped corrupts every statistic downstream --
    $HEX[436f6e7472617365f1613130] is counted as 26 characters long with the
    mask '$UUU$dddldlddddddddddlddddddd$' and the baseword 'HEX', when the
    password is really the 12-character 'Contrase\u00f1a10'.

    The bytes are decoded as UTF-8 first, then cp1252, then latin-1. That order
    matters: cracked passwords routinely come from cp1252 wordlists, where 0xf1
    is the '\u00f1' that UTF-8 rejects. Returns (password, was_hex_encoded).
    """
    match = HEX_ENTRY_RE.match(value)
    if not match:
        return value, False
    try:
        raw = bytes.fromhex(match.group(1))
    except ValueError:  # odd number of digits: not a real $HEX entry
        return value, False
    for encoding in ('utf-8', 'cp1252', 'latin-1'):
        try:
            return raw.decode(encoding), True
        except UnicodeDecodeError:
            continue
    return raw.decode('latin-1', 'replace'), True


# --- Keyboard walk patterns ----------------------------------------------

def download_keyboard_walks(offline: bool = False) -> List[str]:
    """Fetches the keyboard pattern list from SecLists (~9,600 patterns).

    Uses urllib from the standard library so the tool does not need `requests`.
    Any failure degrades to the small built-in list; the rest of the report is
    unaffected.
    """
    if offline:
        print('[-] Offline mode: using the built-in keyboard pattern list')
        return get_default_keyboard_walks()
    try:
        req = urllib.request.Request(
            KEYBOARD_WALKS_URL, headers={'User-Agent': 'graphcat'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='replace').strip()
        patterns = content.split()
        if patterns:
            print(f'[-] Loaded {len(patterns)} keyboard patterns from SecLists')
            return patterns
        print('[!] SecLists list is empty. Falling back to the built-in list.')
    except Exception as exc:
        print(f'[!] Could not download the SecLists list: {exc}')
        print('[!] Falling back to the built-in pattern list.')
    return get_default_keyboard_walks()


def get_default_keyboard_walks() -> List[str]:
    """Built-in list used when the download is skipped or fails."""
    return [
        'qwertyuiop', '123456789', '987654321', 'qwertz', 'azerty', 'dvorak',
        'qwerty', 'asdfgh', 'zxcvbn', '12345678', '1qaz2wsx', 'asdf',
    ]


# --- HTML template, used only by the WeasyPrint engine ---
TEMPLATE = '''<html>
<head><title>{{page_title_text}}</title>
<style>
    body { font-family: 'Titillium Web', sans-serif; }
    h1 { text-align: center; font-size:30px; margin-bottom: 30px; }
    h3 { font-size:24px; page-break-after: avoid; }
    table { width: 85%; border-collapse: collapse; margin: 20px auto; page-break-inside: avoid; }
    table, th, td { border: 1px solid black; }
    thead { background-color: #3563EC; color: white; font-size: 18px; }
    th { text-align: center; height: 50px; }
    td { font-size: 16px; padding: 5px; }
    img { 
        width: 80%; 
        max-width: 700px; 
        height: auto; 
        display: block; 
        margin: 20px auto; 
    }
    .section {
        page-break-inside: avoid;
        margin-bottom: 30px;
    }
    .note { font-size:12px; color:#555; text-align:center; margin: 5px 0; }
    #footer { font-size:8px; text-align:center; margin-top: 30px; }
    p { font-size: 16px; }
</style>
</head>
<body>
<h1>{{title_text}}</h1>
<p>Total hashes: <b>{{total_user}}</b></p>
<p>Passwords found: <b>{{cracked}}</b></p>
<p>Not found: <b>{{not_cracked}}</b></p>
<p>Recovery rate: <b>{{cracked_pct}}%</b></p>

<!-- Section: Recovery Rate -->
<div class="section">
    <h3>Recovery Rate</h3>
    <img src='{{img_found}}'>
</div>

<!-- Section: Uniqueness -->
<div class="section">
    <h3>Uniqueness</h3>
    <p style="white-space: pre-line;">{{uniqueness_text}}</p>
    {% if top_families %}
    <table>
        <thead><tr><th>Root</th><th>Distinct variants</th></tr></thead>
        <tbody>{% for root,count in top_families %}<tr><td>{{root}}</td><td>{{count}}</td></tr>{% endfor %}</tbody>
    </table>
    {% endif %}
    <img src='{{img_uniqueness}}'>
</div>

<!-- Section: Password Strength -->
<div class="section">
    <h3>Password Strength (zxcvbn)</h3>
    <img src='{{img_entropy}}'>
</div>

<!-- Section: Username in Password -->
<div class="section">
    <h3>Username in Password</h3>
    <p>Users with username in password: <b>{{user_in_pass_count}}</b> ({{user_in_pass_pct}}%)</p>
    <img src='{{img_user_in_pass}}'>
</div>

<!-- Section: Temporal Patterns (conditional) -->
{% if img_temporal %}
<div class="section">
    <h3>Temporal Patterns</h3>
    <img src='{{img_temporal}}'>
</div>
{% endif %}

<!-- Section: Keyboard Walks (conditional) -->
{% if img_keyboard %}
<div class="section">
    <h3>Keyboard Walk Patterns</h3>
    <img src='{{img_keyboard}}'>
</div>
{% endif %}

<!-- Section: Format -->
<div class="section">
    <h3>Format Repartition</h3>
    <table>
        <thead><tr><th>Format</th><th>Count</th></tr></thead>
        <tbody>{% for k,v in password_format.items() %}<tr><td>{{k}}</td><td>{{v}}</td></tr>{% endfor %}</tbody>
    </table>
    <img src='{{img_format}}'>
</div>

<!-- Section: Length -->
<div class="section">
    <h3>Length Repartition</h3>
    <table>
        <thead><tr><th>Length</th><th>Count</th></tr></thead>
        <tbody>{% for k,v in length.items() %}<tr><td>{{k}}</td><td>{{v}}</td></tr>{% endfor %}</tbody>
    </table>
    <img src='{{img_length}}'>
</div>

<!-- Section: Top 10 Passwords -->
<div class="section">
    <h3>Top 10 Most Used Passwords</h3>
    <table>
        <thead><tr><th>Password</th><th>Count</th></tr></thead>
        <tbody>{% for k,v in most.items() %}<tr><td>{{k}}</td><td>{{v}}</td></tr>{% endfor %}</tbody>
    </table>
    <img src='{{img_most}}'>
</div>

<!-- Section: Top 10 Basewords -->
<div class="section">
    <h3>Top 10 Basewords</h3>
    <table>
        <thead><tr><th>Baseword</th><th>Count</th></tr></thead>
        <tbody>{% for k,v in baseword.items() %}<tr><td>{{k}}</td><td>{{v}}</td></tr>{% endfor %}</tbody>
    </table>
    <img src='{{img_baseword}}'>
</div>

<!-- Section: Top 10 Number Patterns (conditional) -->
{% if img_numbers %}
<div class="section">
    <h3>Top 10 Number Patterns</h3>
    <table>
        <thead><tr><th>Digits</th><th>Count</th></tr></thead>
        <tbody>{% for k,v in numbers.items() %}<tr><td>{{k}}</td><td>{{v}}</td></tr>{% endfor %}</tbody>
    </table>
    <img src='{{img_numbers}}'>
</div>
{% endif %}

<!-- Section: Top 10 Masks -->
<div class="section">
    <h3>Top 10 Masks</h3>
    <table>
        <thead><tr><th>Mask</th><th>Count</th><th>%</th></tr></thead>
        <tbody>{% for k,v in masks.items() %}<tr><td>{{k}}</td><td>{{v}}</td><td>{{'%.2f'|format(v/cracked*100)}}%</td></tr>{% endfor %}</tbody>
    </table>
    <img src='{{img_masks}}'>
</div>

<!-- Section: History (conditional) -->
{% if img_history %}
<div class="section">
    <h3>History Similarity</h3>
    <img src='{{img_history}}'>
</div>
{% endif %}

<span id="footer">Generated with graphcat - https://github.com/Orange-Cyberdefense/graphcat</span>
</body></html>
'''

# --- Helper classes ---
class Secret:
    def __init__(self, nthash: str, cleartext: Optional[str] = None):
        self.nthash = nthash
        self.cleartext = cleartext
        self.cracked = (cleartext is not None)

    def define_cleartext(self, cleartext: str):
        self.cracked = True
        self.cleartext = cleartext

class User:
    def __init__(self, username: str, nthash: str, cleartext: Optional[str] = None):
        self.username = username
        self.secret = Secret(nthash, cleartext)
        self.cracked = (cleartext is not None)
        self.history: Optional[Dict[int, Secret]] = None

    def add_into_history(self, index: int, nthash: str, cleartext: Optional[str] = None):
        if self.history is None:
            self.history = {}
        self.history[index] = Secret(nthash, cleartext)

# --- Main class ---
class GraphCat:
    def __init__(self, options):
        self.options = options
        self.timestamp = calendar.timegm(time.gmtime())
        self.potfile = {}
        self.hashes = []
        self.outputdir = Path(options.output_dir) if options.output_dir else Path('.')
        self.outputdir.mkdir(parents=True, exist_ok=True)

        # Load keyboard patterns from SecLists.
        # They are literal strings (they contain '(', '[', '*', '+'...), not
        # regexes, so they are matched as substrings. Sorted longest-first so
        # that 'qwerty123' counts as 'qwerty' and not as the shorter 'qwe'.
        self.keyboard_patterns = sorted(
            {p.lower() for p in download_keyboard_walks(getattr(options, "offline", False)) if p},
            key=len,
            reverse=True,
        )

        # Regexes compiled once for the remaining statistics
        self.re_empty = re.compile(r'^$')
        self.re_numeric = re.compile(r'^[0-9]+$')
        self.re_alpha = re.compile(r'^[a-zA-Z]+$')
        self.re_alpha_num = re.compile(r'^(?=[a-zA-Z0-9]*[0-9])(?=[a-zA-Z0-9]*[a-z])(?=[a-zA-Z0-9]*[A-Z])[a-zA-Z0-9]+$')
        self.re_alpha_special = re.compile(r'^(?=[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[a-z])(?=[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[A-Z])(?=[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?])[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$')
        self.re_num_special = re.compile(r'^(?=[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[0-9])(?=[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?])[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$')
        self.re_alpha_num_special = re.compile(r'^(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[0-9])(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[a-z])(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[A-Z])(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?])[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$')
        self.re_year = re.compile(r'\b(19\d{2}|20[0-2]\d)\b')
        self.re_month = re.compile(r'\b(0?[1-9]|1[0-2])\b')

        self._load_potfile()
        self._load_hashfile()

        self._users = None
        self._cracked_users = None
        self._all_nt_hash = None

    # --- File loading ---
    def _load_potfile(self):
        print('[-] Parsing potfile...')
        if not self.options.potfile:
            return
        pot = {}
        hex_entries = 0
        with open(self.options.potfile, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        for line in tqdm(lines, desc='Loading potfile', unit=' lines'):
            line = line.rstrip('\n')
            if ':' not in line:
                continue
            parts = line.split(':', 1)
            if self.options.john:
                if '$NT$' in parts[0]:
                    parts[0] = parts[0].replace('$NT$', '')
                else:
                    continue
            cleartext, was_hex = decode_potfile_value(parts[1])
            hex_entries += was_hex
            pot[parts[0].lower()] = cleartext
        self.potfile = pot
        if not self.potfile:
            print('[!] No entries in potfile. Exiting.')
            sys.exit(1)
        print(f'[-] Loaded {len(self.potfile)} entries from potfile')
        if hex_entries:
            print(f'[-] Decoded {hex_entries} $HEX[...] entries into cleartext')

    def _load_hashfile(self):
        print('[-] Parsing hashfile...')
        if not self.options.hashfile:
            return
        with open(self.options.hashfile, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        hashes = []
        if self.options.format in ['1', '2']:
            hashes = [line.rstrip('\n') for line in tqdm(lines, desc='Loading hashfile', unit=' lines')]
        elif self.options.format == '3':
            for line in tqdm(lines, desc='Loading hashfile (secretsdump)', unit=' lines'):
                if '$:' not in line and '$_history' not in line and ':::' in line:
                    hashes.append(line.rstrip('\n').split(':::')[0])
        else:
            print('[!] Unknown format')
            sys.exit(1)
        self.hashes = hashes
        if not self.hashes:
            print('[!] No entries in hashfile. Exiting.')
            sys.exit(1)
        print(f'[-] Loaded {len(self.hashes)} entries from hashfile')

    # --- Analysis methods ---
    ROOT_MIN_LEN = 3

    def password_root(self, password: str) -> str:
        """Reduces a password to its alphabetic root.

        'Nacional12', 'nacional13!' and 'Nacional2024' all collapse to
        'nacional'. Used to tell a genuinely new password apart from a fresh
        coat of paint on an old one.

        Only the longest contiguous run of letters is kept - stripping digits
        and symbols from the whole string and concatenating what's left would
        splice unrelated fragments together across a digit gap (e.g.
        'Ba1nco2fie' collapsing to 'bancofie' despite that word never
        appearing in the password), producing roots that don't match any
        real substring and disagree with the basewords analysis, which only
        ever looks at contiguous runs.
        """
        runs = re.findall(r'[a-z]+', password.lower())
        return max(runs, key=len) if runs else ''

    def analyze_uniqueness(self) -> dict:
        """Splits cracked accounts into duplicates, variations and unique.

        Counting distinct strings overstates diversity badly: 'nacional12' and
        'nacional13' are two distinct strings but one idea, and an attacker who
        cracks either gets the other from a single rule. Accounts are therefore
        placed in three buckets:

          duplicate  - the exact same string as another account
          variation  - a distinct string, but sharing its alphabetic root with
                       another distinct password in the set
          unique     - a distinct string with a root nobody else shares

        Passwords with fewer than ROOT_MIN_LEN letters (pure digits, symbol
        soup) have no meaningful root, so they are never grouped as variations
        and fall through to unique unless they are exact duplicates.
        """
        passwords = list(self.cracked_users.values())
        total = len(passwords)
        counts = Counter(passwords)
        distinct = list(counts)

        families: Dict[str, set] = {}
        for password in distinct:
            root = self.password_root(password)
            if len(root) >= self.ROOT_MIN_LEN:
                families.setdefault(root, set()).add(password)

        varied = {p for members in families.values() if len(members) > 1
                  for p in members}

        duplicate = total - len(distinct)
        variation = sum(1 for p in distinct if p in varied)
        unique = len(distinct) - variation

        pct = lambda n: round((n / total) * 100, 2) if total else 0.0
        top_families = sorted(
            ((root, len(members)) for root, members in families.items()
             if len(members) > 1),
            key=lambda item: item[1], reverse=True)[:5]

        return {
            'total': total,
            'distinct': len(distinct),
            'duplicate': duplicate,
            'variation': variation,
            'unique': unique,
            'distinct_pct': pct(len(distinct)),
            'duplicate_pct': pct(duplicate),
            'variation_pct': pct(variation),
            'unique_pct': pct(unique),
            'top_families': top_families,
        }

    def analyze_number_patterns(self) -> Dict[str, int]:
        """Counts runs of two or more digits.

        Basewords only capture the alphabetic half of a password. The digits
        appended to them are just as reusable when building rules, and a year
        or a repeated PIN showing up hundreds of times is a finding of its own.
        """
        patterns = Counter()
        for password in self.cracked_users.values():
            for run in re.findall(r'\d{2,}', password):
                patterns[run] += 1
        return dict(patterns)

    def analyze_entropy(self) -> Dict[int, int]:
        scores = Counter()
        for pwd in tqdm(self.cracked_users.values(), desc='Calculating entropy', unit=' passwords'):
            # zxcvbn raises IndexError on an empty string; a blank password is
            # by definition the weakest one (score 0).
            scores[zxcvbn(pwd)['score'] if pwd else 0] += 1
        return dict(scores)

    def analyze_username_in_password(self) -> int:
        count = 0
        for user, pwd in self.cracked_users.items():
            if not pwd:
                continue
            # secretsdump prefixes the domain ('DOMAIN\\j.smith'), which never
            # appears inside a password. Comparing the raw value would silently
            # score every account as a miss, so match on the bare username.
            bare = user.rsplit('\\', 1)[-1].lower()
            if bare and bare in pwd.lower():
                count += 1
        return count

    def analyze_temporal_patterns(self) -> Tuple[Dict[str, int], Dict[int, int]]:
        years = Counter()
        months = Counter()
        for pwd in self.cracked_users.values():
            for y in self.re_year.findall(pwd):
                years[y] += 1
            for m in self.re_month.findall(pwd):
                # Normalize to int: the regex matches both '1' and '01' for
                # January, and keeping them as separate string keys splits
                # the same month into two bars and breaks numeric sorting
                # ('1', '10', '11', '12', '2', ... instead of 1..12).
                months[int(m)] += 1
        return dict(years), dict(months)

    def analyze_keyboard_walks(self) -> Dict[str, int]:
        patterns = Counter()
        for pwd in self.cracked_users.values():
            pwd_lower = pwd.lower()
            for pat in self.keyboard_patterns:
                if pat in pwd_lower:
                    patterns[pat] += 1
                    break  # Count only the longest matching pattern
        return dict(patterns)

    def analyze_format(self) -> Dict[str, int]:
        fmt = Counter()
        for pwd in self.cracked_users.values():
            if self.re_empty.fullmatch(pwd):
                fmt['Empty'] += 1
            elif self.re_numeric.fullmatch(pwd):
                fmt['Numeric'] += 1
            elif self.re_alpha.fullmatch(pwd):
                fmt['Alpha'] += 1
            elif self.re_alpha_num.fullmatch(pwd):
                fmt['Alpha+Num'] += 1
            elif self.re_alpha_special.fullmatch(pwd):
                fmt['Alpha+Special'] += 1
            elif self.re_num_special.fullmatch(pwd):
                fmt['Num+Special'] += 1
            elif self.re_alpha_num_special.fullmatch(pwd):
                fmt['Alpha+Num+Special'] += 1
            else:
                fmt['Other'] += 1
        return dict(fmt)

    # --- Charts ---
    def _create_pie(self, data: Dict[str, int], title: str, colors=None, donut=True):
        fig, ax = plt.subplots(figsize=(8, 6))
        wedges, texts, autotexts = ax.pie(
            data.values(),
            labels=None,
            autopct='%.1f%%',
            colors=colors or COLORS_QUALITATIVE,
            wedgeprops={'edgecolor': 'white', 'linewidth': 2},
            startangle=90,
            textprops={'fontsize': 10, 'fontweight': 'bold'},
            pctdistance=0.75,
        )
        if donut:
            centre_circle = plt.Circle((0, 0), 0.60, fc='white')
            ax.add_artist(centre_circle)
        ax.legend(wedges, data.keys(),
                  title=title,
                  loc='center left',
                  bbox_to_anchor=(1, 0.5),
                  fontsize=9,
                  title_fontsize=11)
        ax.set_title(title, fontsize=16, fontweight='bold', pad=15)
        plt.tight_layout(pad=1.0)
        return fig

    def _create_bar(self, data: Dict[str, int], title: str, xlabel='', ylabel='Count', color='#3563EC', horizontal=False):
        items = list(data.items())
        if not items:
            fig, ax = plt.subplots(figsize=(10, 6))
            return fig
        labels, values = zip(*items)
        # Escape characters matplotlib would read as mathtext
        labels = [str(label).replace('$', '\\$') for label in labels]

        if horizontal:
            # Size the left margin to the longest label instead of a fixed
            # fraction: a short label like 'qwerty' left acres of empty
            # margin, while a long SecLists pattern overflowed the fixed
            # 45% and ran into the bars/count annotations.
            max_len = max(len(label) for label in labels)
            left_margin = min(0.6, max(0.18, 0.09 + 0.011 * max_len))
            fig, ax = plt.subplots(figsize=(14, 7))
            plt.subplots_adjust(left=left_margin)
        else:
            fig, ax = plt.subplots(figsize=(10, 6))

        if horizontal:
            ax.barh(labels, values, color=color, edgecolor='white')
            ax.set_xlabel(ylabel, fontsize=13)
            ax.set_ylabel(xlabel, fontsize=13)
            ax.set_yticks(range(len(labels)))
            # ha='right' anchors the label's right edge at the axis so the
            # text grows leftward into the margin; 'left' (the previous
            # value) anchored the left edge there instead, so the text grew
            # rightward and overlapped the bars themselves.
            ax.set_yticklabels(labels, ha='right')
            ax.tick_params(axis='y', labelsize=9)
            ax.set_xlim(right=max(values) * 1.15)
            for i, v in enumerate(values):
                ax.text(v + (max(values)*0.02), i, str(v), va='center', fontsize=9)
        else:
            ax.bar(labels, values, color=color, edgecolor='white')
            ax.set_xlabel(xlabel, fontsize=13)
            ax.set_ylabel(ylabel, fontsize=13)
            ax.set_xticks(range(len(labels)))
            ax.set_xticklabels(labels, ha='right', rotation=45)
            ax.tick_params(axis='x', labelsize=9)
            max_val = max(values) if values else 1
            for i, v in enumerate(values):
                ax.text(i, v + (max_val*0.02), str(v), ha='center', fontsize=9)

        ax.set_title(title, fontsize=16, fontweight='bold')
        plt.tight_layout(pad=1.5)
        return fig

    def _save_figure(self, dirpath: Path, filename: str, fig=None, dpi=150):
        if fig is None:
            fig = plt.gcf()
        plt.tight_layout(pad=1.5)
        fig.savefig(dirpath / filename, dpi=dpi, bbox_inches='tight')
        if self.options.export_charts:
            fig.savefig(self.outputdir / filename, dpi=200, bbox_inches='tight')
        plt.close(fig)

    # --- Report generation ---
    def gen_stat(self):
        print('[-] Generating graphs...')
        dirpath = Path(tempfile.mkdtemp())

        total_user = len(self.all_nt_hash)
        if not self.cracked_users:
            print('[!] No cracked users. Exiting.')
            sys.exit(0)

        cracked = len(self.cracked_users)
        not_cracked = total_user - cracked
        cracked_pct = round((cracked / total_user) * 100, 2) if total_user else 0

        # 1. Cracked
        fig = self._create_pie({'Recovered': cracked, 'Not recovered': not_cracked}, 'Recovery Rate', colors=['#07C136','#DC1215'])
        self._save_figure(dirpath, 'cracked.png', fig)

        # 2. Uniqueness: unique vs variation-of-another vs exact duplicate
        uniq = self.analyze_uniqueness()
        uniqueness_slices = {
            'Unique': uniq['unique'],
            'Variation of another': uniq['variation'],
            'Exact duplicate': uniq['duplicate'],
        }
        fig = self._create_pie({k: v for k, v in uniqueness_slices.items() if v},
                               'Uniqueness', colors=['#4CAF50', '#FFB300', '#FF5722'])
        self._save_figure(dirpath, 'uniqueness.png', fig)

        # 3. Entropy
        entropy = self.analyze_entropy()
        labels = {0:'Very Weak',1:'Weak',2:'Medium',3:'Strong',4:'Very Strong'}
        entropy_named = {labels.get(k,str(k)): v for k,v in entropy.items()}
        fig = self._create_bar(entropy_named, 'Password Strength (zxcvbn)', xlabel='Score', ylabel='Count', color=COLORS_SEQUENTIAL[:5])
        self._save_figure(dirpath, 'entropy.png', fig)

        # 4. Username in password
        user_in_pass = self.analyze_username_in_password()
        user_in_pass_pct = round((user_in_pass / cracked) * 100, 2) if cracked else 0
        fig = self._create_pie({'Contain Username': user_in_pass, 'Not Contain': cracked - user_in_pass}, 'Username in Password', colors=['#FF9800','#2196F3'])
        self._save_figure(dirpath, 'user_in_pass.png', fig)

        # 5. Temporal
        years, months = self.analyze_temporal_patterns()
        if years or months:
            # Only draw the panels that have data: allocating both unconditionally
            # left an empty pair of axes in the report whenever one was missing.
            panels = [p for p in ('years', 'months') if locals()[p]]
            fig, axes = plt.subplots(1, len(panels), figsize=(7 * len(panels), 5),
                                     squeeze=False)
            month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                           'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            for ax, panel in zip(axes[0], panels):
                if panel == 'months':
                    # Keys are ints 1-12: sort numerically and use month
                    # abbreviations instead of raw digits so Jan (1) isn't
                    # confused with the 1 in '2018' or similar.
                    data = {month_names[k - 1]: v for k, v in sorted(months.items())}
                else:
                    data = dict(sorted(years.items()))
                palette = COLORS_SEQUENTIAL if panel == 'years' else COLORS_QUALITATIVE
                ax.bar(data.keys(), data.values(), color=palette[:len(data)])
                ax.set_title(panel.capitalize(), fontsize=14)
                ax.tick_params(axis='x', rotation=45)
                for label in ax.get_xticklabels():
                    label.set_ha('right')
            self._save_figure(dirpath, 'temporal.png', fig)

        # 6. Keyboard walks
        kb = self.analyze_keyboard_walks()
        if kb:
            sorted_kb = dict(sorted(kb.items(), key=lambda x: x[1], reverse=True)[:10])
            fig = self._create_bar(sorted_kb, 'Keyboard Walks', xlabel='Pattern', ylabel='Count', color='#FF6F61', horizontal=True)
            self._save_figure(dirpath, 'keyboard.png', fig)

        # 7. Format
        fmt_data = self.analyze_format()
        fig = self._create_pie(fmt_data, 'Password Format', colors=COLORS_QUALITATIVE[:len(fmt_data)])
        self._save_figure(dirpath, 'format.png', fig)

        # 8. Length
        length_bins = {'0-5':0, '6':0, '7':0, '8':0, '9':0, '10':0, '11':0, '12':0, '13':0, '14':0, '15':0, '15+':0}
        for pwd in self.cracked_users.values():
            l = len(pwd)
            if l <= 5:
                length_bins['0-5'] += 1
            elif l <= 14:
                length_bins[str(l)] += 1
            elif l == 15:
                length_bins['15'] += 1
            else:
                length_bins['15+'] += 1
        length_bins = {k:v for k,v in length_bins.items() if v > 0}
        fig = self._create_bar(length_bins, 'Password Length', xlabel='Length', ylabel='Count', color='#3563EC')
        self._save_figure(dirpath, 'length.png', fig)

        # 9. Top 10 passwords, basewords, masks
        c_pass = Counter()
        c_base = Counter()
        c_mask = Counter()
        for pwd in self.cracked_users.values():
            c_pass[pwd if pwd else '[EMPTY]'] += 1
            for w in re.findall(r'[a-zA-Z]{4,20}', pwd):
                c_base[w] += 1
            c_mask[self.gen_mask(pwd)] += 1

        most = {k:v for k,v in c_pass.most_common(10) if v > 1}
        basewords = {k:v for k,v in c_base.most_common(10) if v > 1}
        masks = dict(c_mask.most_common(10))

        if most:
            fig = self._create_bar(most, 'Top 10 Passwords', xlabel='Password', ylabel='Count', color='#E67E22')
            self._save_figure(dirpath, 'most.png', fig)
        if basewords:
            fig = self._create_bar(basewords, 'Top 10 Basewords', xlabel='Baseword', ylabel='Count', color='#8E44AD')
            self._save_figure(dirpath, 'basewords.png', fig)
        numbers = self.analyze_number_patterns()
        top_numbers = dict(sorted(numbers.items(), key=lambda x: x[1], reverse=True)[:10])
        top_numbers = {k: v for k, v in top_numbers.items() if v > 1}
        if top_numbers:
            fig = self._create_bar(top_numbers, 'Top 10 Number Patterns', xlabel='Digits', ylabel='Count', color='#16A085')
            self._save_figure(dirpath, 'numbers.png', fig)

        if masks:
            masks_escaped = {k.replace('$', '\\$'): v for k, v in masks.items()}
            fig = self._create_bar(masks_escaped, 'Top 10 Masks', xlabel='Mask', ylabel='Count', color='#2980B9', horizontal=True)
            self._save_figure(dirpath, 'masks.png', fig)

        # 10. History
        history_reuse = self.analyze_history()
        if history_reuse:
            fig = self._create_pie({'Similar pattern': history_reuse, 'No similar': cracked - history_reuse}, 'History Similarity', colors=['#E74C3C','#2ECC71'])
            self._save_figure(dirpath, 'history.png', fig)

        # --- Assemble the report model, engine-agnostic ---
        report = {
            'total_user': total_user,
            'cracked': cracked,
            'not_cracked': not_cracked,
            'cracked_pct': cracked_pct,
            'uniq': uniq,
            'numbers': top_numbers,
            'user_in_pass': user_in_pass,
            'user_in_pass_pct': user_in_pass_pct,
            'fmt_data': fmt_data,
            'length_bins': length_bins,
            'most': most,
            'basewords': basewords,
            'masks': masks,
            'has_numbers': bool(top_numbers),
            'has_temporal': bool(years or months),
            'has_keyboard': bool(kb),
            'has_history': bool(history_reuse),
        }

        print('[-] Generating report...')
        filename = f'graphcat_{self.timestamp}.pdf'
        outpath = self.outputdir / filename

        engine = self._resolve_engine()
        print(f'[-] PDF engine: {engine}')
        if engine == 'weasyprint':
            self._render_weasyprint(report, dirpath, outpath)
        else:
            self._render_fpdf(report, dirpath, outpath)

        shutil.rmtree(dirpath)
        print(f'[-] Report available at {outpath}')

    def _resolve_engine(self) -> str:
        """Picks the PDF backend, honouring -pdf-engine."""
        wanted = self.options.pdf_engine
        available, reason = weasyprint_status()
        if wanted == 'weasyprint':
            if not available:
                if 'system libraries' in reason:
                    print(SYSTEM_LIB_HINT.format(reason=reason))
                else:
                    print(f'[!] WeasyPrint requested but unavailable: {reason}')
                    print('[!] Install it with: pip install "graphcat-extended[weasyprint]"')
                sys.exit(1)
            return 'weasyprint'
        if wanted == 'fpdf':
            return 'fpdf'
        # auto: best fidelity available, never fatal
        return 'weasyprint' if available else 'fpdf'

    # --- Engine 1: fpdf2 (pure Python, no system libraries) ---------------
    def _render_fpdf(self, report: dict, dirpath: Path, outpath: Path):
        sections = self._sections(report, dirpath)
        pdf = _ReportPDF()
        pdf.setup_font()
        pdf.add_page()

        pdf.set_font(pdf.font_name, 'B', 22)
        pdf.set_text_color(*INK)
        pdf.cell(0, 12, 'Password Cracking Report', align='C', new_x='LMARGIN', new_y='NEXT')
        pdf.ln(4)

        summary = [
            ('Total hashes', f"{report['total_user']}"),
            ('Passwords found', f"{report['cracked']}"),
            ('Not found', f"{report['not_cracked']}"),
            ('Recovery rate', f"{report['cracked_pct']}%"),
        ]
        pdf.set_font(pdf.font_name, '', 11)
        for label, value in summary:
            pdf.set_text_color(*MUTED)
            pdf.cell(45, 7, f'{label}:')
            pdf.set_text_color(*INK)
            pdf.set_font(pdf.font_name, 'B', 11)
            pdf.cell(0, 7, value, new_x='LMARGIN', new_y='NEXT')
            pdf.set_font(pdf.font_name, '', 11)
        pdf.ln(6)

        for title, text, table, image in sections:
            pdf.section(title, text, table, image)

        pdf.output(str(outpath))

    # --- Engine 2: WeasyPrint (HTML/CSS, needs Pango + Cairo) -------------
    def _render_weasyprint(self, report: dict, dirpath: Path, outpath: Path):
        from jinja2 import Environment, FileSystemLoader
        from weasyprint import HTML, CSS

        with open(dirpath / 'template.html', 'w', encoding='utf-8') as f:
            f.write(TEMPLATE)

        env = Environment(loader=FileSystemLoader(str(dirpath)))
        template = env.get_template('template.html')

        def img(name, present=True):
            return str(dirpath / name) if present else ''

        html = template.render(
            page_title_text='Password Cracking Report',
            title_text='Password Cracking Report',
            total_user=report['total_user'],
            cracked=report['cracked'],
            not_cracked=report['not_cracked'],
            cracked_pct=report['cracked_pct'],
            uniqueness_text=self._uniqueness_text(report['uniq']),
            top_families=report['uniq']['top_families'],
            numbers=report['numbers'],
            user_in_pass_count=report['user_in_pass'],
            user_in_pass_pct=report['user_in_pass_pct'],
            password_format=report['fmt_data'],
            length=report['length_bins'],
            most=report['most'],
            baseword=report['basewords'],
            masks=report['masks'],
            img_found=img('cracked.png'),
            img_uniqueness=img('uniqueness.png'),
            img_entropy=img('entropy.png'),
            img_user_in_pass=img('user_in_pass.png'),
            img_temporal=img('temporal.png', report['has_temporal']),
            img_keyboard=img('keyboard.png', report['has_keyboard']),
            img_format=img('format.png'),
            img_length=img('length.png'),
            img_most=img('most.png', bool(report['most'])),
            img_baseword=img('basewords.png', bool(report['basewords'])),
            img_masks=img('masks.png', bool(report['masks'])),
            img_numbers=img('numbers.png', report['has_numbers']),
            img_history=img('history.png', report['has_history']),
        )

        with open(dirpath / 'report.html', 'w', encoding='utf-8') as f:
            f.write(html)

        css = CSS(string='''
            @page { size: A4; margin: 1cm; @bottom-right {
                font-size: 10px; content: counter(page) " / " counter(pages);
            }}
            .section { page-break-inside: avoid; }
            h3 { page-break-after: avoid; font-size:24px; }
            table { page-break-inside: avoid; width: 85%; border-collapse: collapse; margin: 20px auto; }
            img { width: 80%; max-width: 700px; height: auto; display: block; margin: 20px auto; }
            h1 { text-align: center; font-size:30px; }
            thead { background-color: #3563EC; color: white; font-size: 18px; }
            th { text-align: center; height: 50px; }
            td { font-size: 16px; padding: 5px; }
            #footer { font-size:8px; text-align:center; margin-top: 30px; }
            .note { font-size:12px; color:#555; text-align:center; margin: 5px 0; }
            p { font-size: 16px; }
        ''')

        HTML(str(dirpath / 'report.html')).write_pdf(str(outpath), stylesheets=[css])

    @staticmethod
    def _uniqueness_text(uniq: dict) -> str:
        """Explains why distinct-string counting overstates diversity."""
        text = (
            f"Distinct passwords: {uniq['distinct']} of {uniq['total']} "
            f"({uniq['distinct_pct']}%).\n"
            f"Of those, {uniq['unique']} ({uniq['unique_pct']}%) are genuinely "
            f"unique, while {uniq['variation']} ({uniq['variation_pct']}%) are "
            f"only a variation of another password in this set - a different "
            f"string sharing the same root, such as 'nacional12' next to "
            f"'nacional13'. A further {uniq['duplicate']} "
            f"({uniq['duplicate_pct']}%) reuse another account's password "
            f"verbatim.\n"
            f"Counting distinct strings alone would report "
            f"{uniq['distinct_pct']}% diversity; once variations are folded in, "
            f"effective diversity is {uniq['unique_pct']}%. Variations matter "
            f"because a single cracking rule turns one of them into all the "
            f"others."
        )
        return text

    @staticmethod
    def _families_table(uniq: dict):
        """Largest baseword families, i.e. the roots with the most variants."""
        if not uniq['top_families']:
            return None
        return (['Root', 'Distinct variants'],
                [[root, count] for root, count in uniq['top_families']])

    def _sections(self, report: dict, dirpath: Path):
        """Section descriptors: (title, paragraph, (headers, rows), image)."""
        cracked = report['cracked']
        pct = lambda v: f'{v / cracked * 100:.2f}%' if cracked else '0.00%'

        sections = [
            ('Recovery Rate', None, None, dirpath / 'cracked.png'),
            ('Uniqueness', self._uniqueness_text(report['uniq']),
             self._families_table(report['uniq']), dirpath / 'uniqueness.png'),
            ('Password Strength (zxcvbn)', None, None, dirpath / 'entropy.png'),
            ('Username in Password',
             f"Users with their username in the password: {report['user_in_pass']} "
             f"({report['user_in_pass_pct']}%)",
             None, dirpath / 'user_in_pass.png'),
        ]
        if report['has_temporal']:
            sections.append(('Temporal Patterns', None, None, dirpath / 'temporal.png'))
        if report['has_keyboard']:
            sections.append(('Keyboard Walk Patterns', None, None, dirpath / 'keyboard.png'))

        sections += [
            ('Format Repartition', None,
             (['Format', 'Count'], [[k, v] for k, v in report['fmt_data'].items()]),
             dirpath / 'format.png'),
            ('Length Repartition', None,
             (['Length', 'Count'], [[k, v] for k, v in report['length_bins'].items()]),
             dirpath / 'length.png'),
        ]
        if report['most']:
            sections.append(('Top 10 Most Used Passwords', None,
                             (['Password', 'Count'], [[k, v] for k, v in report['most'].items()]),
                             dirpath / 'most.png'))
        if report['basewords']:
            sections.append(('Top 10 Basewords', None,
                             (['Baseword', 'Count'], [[k, v] for k, v in report['basewords'].items()]),
                             dirpath / 'basewords.png'))
        if report['has_numbers']:
            sections.append(('Top 10 Number Patterns', None,
                             (['Digits', 'Count'], [[k, v] for k, v in report['numbers'].items()]),
                             dirpath / 'numbers.png'))
        if report['masks']:
            sections.append(('Top 10 Masks', None,
                             (['Mask', 'Count', '%'],
                              [[k, v, pct(v)] for k, v in report['masks'].items()]),
                             dirpath / 'masks.png'))
        if report['has_history']:
            sections.append(('History Similarity', None, None, dirpath / 'history.png'))
        return sections

    # --- Helper methods ---
    def gen_mask(self, password: str) -> str:
        mask = []
        for ch in password:
            if ch in string.digits:
                mask.append('d')
            elif ch in string.ascii_lowercase:
                mask.append('l')
            elif ch in string.ascii_uppercase:
                mask.append('U')
            else:
                mask.append('$')
        return ''.join(mask)

    def analyze_history(self) -> int:
        reuse = 0
        for user in self.users.values():
            if not user.cracked or not user.history:
                continue
            for hist in user.history.values():
                if hist.cracked:
                    sim = self._similarity(hist.cleartext, user.secret.cleartext)
                    if sim >= 5 or sim > len(user.secret.cleartext) - 3:
                        reuse += 1
                        break
        return reuse

    def _similarity(self, w1: str, w2: str) -> int:
        max_chain = 0
        current = 0
        for diff in difflib.ndiff(w1, w2):
            if diff[0] == ' ':
                current += 1
                if current > max_chain:
                    max_chain = current
            else:
                current = 0
        return max_chain

    def parse_ntds_line(self, line: str):
        parts = line.split(':')
        return parts[0], parts[3].lower()

    @property
    def users(self) -> Dict[str, User]:
        if self._users is not None:
            return self._users
        users = {}
        hist_lines = []
        if self.options.format == '1':
            for i, h in enumerate(self.hashes):
                h = h.lower()
                users[f'user_{i}'] = User(f'user_{i}', h, self.potfile.get(h))
        elif self.options.format == '2':
            for line in self.hashes:
                username, h = line.split(':')
                h = h.lower()
                users[username] = User(username, h, self.potfile.get(h))
        elif self.options.format == '3':
            for line in self.hashes:
                if '_history' in line:
                    hist_lines.append(line)
                else:
                    username, nthash = self.parse_ntds_line(line)
                    users[username] = User(username, nthash, self.potfile.get(nthash))
            for line in hist_lines:
                username, nthash = self.parse_ntds_line(line)
                user, idx = username.split('_history')
                users[user].add_into_history(int(idx), nthash, self.potfile.get(nthash))
        self._users = users
        return self._users

    @property
    def cracked_users(self) -> Dict[str, str]:
        if self._cracked_users is not None:
            return self._cracked_users
        self._cracked_users = {u.username: u.secret.cleartext for u in self.users.values() if u.cracked}
        return self._cracked_users

    @property
    def all_nt_hash(self) -> List[str]:
        if self._all_nt_hash is not None:
            return self._all_nt_hash
        self._all_nt_hash = [u.secret.nthash for u in self.users.values()]
        return self._all_nt_hash


# --- Pure-Python PDF document -------------------------------------------

class _ReportPDF(FPDF):
    """A4 report built with fpdf2. No system libraries involved."""

    IMG_WIDTH = 150  # mm, out of 180 usable

    def __init__(self):
        super().__init__(format='A4', unit='mm')
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(True, margin=18)
        self.font_name = 'helvetica'
        self.unicode_ok = False

    def setup_font(self):
        """Embeds DejaVu Sans, which ships with matplotlib.

        fpdf2's built-in fonts only cover Latin-1, and passwords routinely
        contain characters outside it. matplotlib is already a hard dependency,
        so its bundled DejaVu is always on disk: no extra download, no extra
        package, and coverage for Latin, Greek and Cyrillic.
        """
        ttf_dir = Path(matplotlib.get_data_path()) / 'fonts' / 'ttf'
        regular = ttf_dir / 'DejaVuSans.ttf'
        bold = ttf_dir / 'DejaVuSans-Bold.ttf'
        if regular.is_file():
            self.add_font('DejaVu', '', str(regular))
            self.add_font('DejaVu', 'B', str(bold if bold.is_file() else regular))
            self.font_name = 'DejaVu'
            self.unicode_ok = True
        return self.font_name

    def clean(self, text) -> str:
        """Keeps text renderable by the active font.

        With DejaVu embedded almost everything passes through untouched; only
        codepoints the font has no glyph for (CJK, most emoji) are replaced, so
        an exotic password degrades to a placeholder instead of aborting the
        whole report.
        """
        text = str(text)
        if not self.unicode_ok:
            return text.encode('latin-1', 'replace').decode('latin-1')
        return ''.join(c if ord(c) < 0x2E80 else '�' for c in text)

    def footer(self):
        self.set_y(-15)
        self.set_font(self.font_name, '', 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, f'{self.page_no()} / {{nb}}', align='R')

    # --- Layout primitives ---
    def _space_left(self) -> float:
        return self.h - self.b_margin - self.get_y()

    def _image_height(self, path: Path) -> float:
        from PIL import Image
        with Image.open(path) as im:
            width, height = im.size
        return self.IMG_WIDTH * height / width

    def section(self, title: str, text: Optional[str],
                table: Optional[Tuple[List[str], List[list]]],
                image: Optional[Path]):
        """Writes one section, keeping its heading with its content.

        Estimates the height of the whole block up front and starts a new page
        when it does not fit, which is what stops a heading from being orphaned
        at the bottom of a page.
        """
        needed = 12
        if text:
            needed += 8
        if table:
            needed += 8 * (len(table[1]) + 1)
        if image and Path(image).is_file():
            needed += self._image_height(Path(image)) + 4
        usable = self.h - self.t_margin - self.b_margin
        if needed > self._space_left() and needed <= usable:
            self.add_page()

        self.set_font(self.font_name, 'B', 15)
        self.set_text_color(*ACCENT)
        self.cell(0, 9, self.clean(title), new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.4)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

        if text:
            self.set_font(self.font_name, '', 10)
            self.set_text_color(*INK)
            self.multi_cell(0, 5.5, self.clean(text), new_x='LMARGIN', new_y='NEXT')
            self.ln(2)

        if table:
            self.add_table(*table)

        if image and Path(image).is_file():
            self.add_image(Path(image))

        self.ln(5)

    def add_table(self, headers: List[str], rows: List[list]):
        self.set_font(self.font_name, '', 9)
        self.set_text_color(*INK)
        self.set_draw_color(190, 190, 190)  # the heading rule left it accent-blue
        self.set_line_width(0.15)
        heading = FontFace(emphasis='BOLD', color=(255, 255, 255), fill_color=ACCENT)
        with self.table(width=150, align=Align.C, line_height=6,
                        text_align=Align.C, headings_style=heading,
                        borders_layout='ALL') as table:
            row = table.row()
            for cell in headers:
                row.cell(self.clean(cell))
            for data in rows:
                row = table.row()
                for cell in data:
                    row.cell(self.clean(cell))
        self.ln(3)

    def add_image(self, path: Path):
        height = self._image_height(path)
        width = self.IMG_WIDTH
        available = self._space_left()
        if height > available:
            usable = self.h - self.t_margin - self.b_margin
            if height <= usable:
                self.add_page()
            else:  # taller than a whole page: scale to fit
                height = usable
                width = height * self.IMG_WIDTH / self._image_height(path)
        top = self.get_y()
        self.image(str(path), x=(self.w - width) / 2, y=top, w=width, h=height)
        self.set_y(top + height)


# --- Entry point ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='GraphCat - Advanced Password Cracking Report')
    parser.add_argument('-potfile', required=True, help='Hashcat potfile')
    parser.add_argument('-hashfile', required=True, help='Hash file')
    parser.add_argument('-john', action='store_true', help='John potfile format')
    parser.add_argument('-format', default='3',
                        help='Format: 1=hash, 2=username:hash, 3=secretsdump')
    parser.add_argument('-pdf-engine', default='auto',
                        choices=['auto', 'fpdf', 'weasyprint'],
                        help='PDF backend. fpdf is pure Python and needs no '
                             'system libraries; weasyprint renders the HTML '
                             'template but needs Pango/Cairo. auto (default) '
                             'uses weasyprint when it is usable, else fpdf')
    parser.add_argument('-export-charts', action='store_true',
                        help='Export PNG charts')
    parser.add_argument('-output-dir', default='.', help='Output directory')
    parser.add_argument('-offline', action='store_true',
                        help='Skip the SecLists download and use the built-in '
                             'keyboard pattern list')
    parser.add_argument('-debug', action='store_true', help='Debug mode')
    args = parser.parse_args()

    try:
        gc = GraphCat(args)
        gc.gen_stat()
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        print(f'ERROR: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
