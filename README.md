# graphcat-extended

Turns the output of a password cracking run (Active Directory / NTDS plus hashcat
or John) into a PDF report full of charts and statistics.

Extended fork of [Orange-Cyberdefense/graphcat](https://github.com/Orange-Cyberdefense/graphcat).
It adds uniqueness, strength scoring (zxcvbn), username-in-password, temporal
patterns and keyboard-walk analysis, plus chart export and an output directory
flag.

**Installs with `pip` alone — no system packages, no compiler.** The default PDF
engine is pure Python, so the `cannot load library 'libgobject-2.0-0'` class of
error cannot happen.

> **Authorised use only.** This is a security auditing tool. Its inputs and
> outputs contain cleartext passwords belonging to real people — handle them
> accordingly.

---

## What it produces

A single `graphcat_<timestamp>.pdf` containing:

| Section | What it shows |
| --- | --- |
| Recovery Rate | Cracked hashes against the total |
| Uniqueness | Genuinely unique passwords vs. variations vs. exact duplicates |
| Password Strength | zxcvbn score (0–4) across the set |
| Username in Password | Accounts whose password contains their own username |
| Temporal Patterns | Years and months embedded in passwords |
| Keyboard Walks | Patterns such as `qwerty` or `1qaz2wsx` |
| Format Repartition | Composition: alphabetic, numeric, with symbols… |
| Length Repartition | Length distribution |
| Top 10 Passwords | Most frequently repeated passwords |
| Top 10 Basewords | Most common alphabetic roots |
| Top 10 Number Patterns | Most common digit runs (`2024`, `123`…) |
| Top 10 Masks | hashcat-style masks (`Ulllldddd$`) |
| History Similarity | Accounts rotating their password with minimal changes |

Temporal patterns, keyboard walks, number patterns and history only appear when
there is something to show. History needs `-format 3` with the `_history` lines
from the dump.

Add `-export-charts` to also drop every chart as a standalone PNG, ready to paste
into the engagement report.

---

## Installation

### 1. Get the code

```bash
git clone https://github.com/<your-user>/graphcat-extended.git
cd graphcat-extended
```

### 2. Install

Use a virtual environment so you do not disturb the system Python.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install .
```

That puts a `graphcat` command on your `PATH`. It works on any Python from 3.8
up to and including the current release — every dependency ships a wheel, and the
PDF engine is a pure-Python `py3-none-any` package, so a new Python version never
leaves you waiting for someone to publish a compiled build.

<details>
<summary>Other ways to install</summary>

**pipx** — a global, isolated command; the nicest option for daily use:

```bash
pipx install .
```

**Editable** — for hacking on the code:

```bash
pip install -e .
```

**No install at all** — dependencies only, then run the script directly:

```bash
pip install -r requirements.txt
python3 graphcat.py -h
```

**Hash-verified** — pinned versions, every artifact checked against a known
SHA-256. Preferred when the machine handles client data:

```bash
pip install --require-hashes -r requirements.lock
pip install --no-deps .
```

</details>

### 3. Check it works

```bash
python3 examples/generate_sample.py
graphcat -potfile examples/sample.pot -hashfile examples/sample.ntds -format 3
```

It should end with `[-] Report available at graphcat_<number>.pdf`. The sample
data is synthetic — invented users and passwords, generated locally.

### Optional: the WeasyPrint engine

The default engine needs nothing beyond pip. WeasyPrint is offered as an
alternative that renders the HTML/CSS template instead, which some people prefer
the look of. It is **not required**, and it is the component that needs system
libraries pip cannot install:

```bash
# Debian / Ubuntu / Kali / Parrot
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    libcairo2 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info
# Fedora / RHEL:  sudo dnf install -y pango cairo gdk-pixbuf2 libffi-devel
# Arch:           sudo pacman -S pango cairo gdk-pixbuf2 libffi
# macOS:          brew install pango cairo gdk-pixbuf libffi

pip install ".[weasyprint]"
graphcat ... -pdf-engine weasyprint
```

---

## Usage

```bash
graphcat -potfile <potfile> -hashfile <hashes> [-format 1|2|3] [options]
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `-potfile` | *(required)* | hashcat potfile (`hash:password`) |
| `-hashfile` | *(required)* | File holding the hashes to analyse |
| `-format` | `3` | Layout of `-hashfile`; see the table below |
| `-john` | off | The potfile came from John the Ripper (`$NT$<hash>` entries) |
| `-pdf-engine` | `auto` | `fpdf`, `weasyprint`, or `auto` — WeasyPrint when usable, otherwise fpdf |
| `-export-charts` | off | Also write each chart as a PNG in the output directory |
| `-output-dir` | `.` | Where to write the PDF and PNGs |
| `-offline` | off | Skip the SecLists download and use the built-in pattern list |
| `-debug` | off | Print the full traceback on failure |

### `-hashfile` formats

| `-format` | Each line holds | Example |
| --- | --- | --- |
| `1` | The NT hash alone | `64f12cddaa88057e06a81b54e73b949b` |
| `2` | `username:hash` | `a.silva:3aea738c96b891502e5b02eac8a614b0` |
| `3` | A `secretsdump.py` dump | `DOM\a.silva:1100:aad3b4…:3aea73…:::` |

Only `-format 3` supports history analysis and username-in-password against real
names. With `-format 1` users are numbered (`user_0`, `user_1`…), which makes that
particular analysis meaningless.

### Typical workflow

```bash
# 1. Dump the domain
secretsdump.py -just-dc DOM/user@10.0.0.1 -outputfile dump

# 2. Crack
hashcat -m 1000 dump.ntds --username -a 0 rockyou.txt -r best64.rule

# 3. Report
graphcat -potfile ~/.local/share/hashcat/hashcat.potfile \
         -hashfile dump.ntds \
         -format 3 \
         -export-charts \
         -output-dir ./report
```

### Examples

```bash
# John potfile instead of hashcat
graphcat -potfile john.pot -hashfile dump.ntds -format 3 -john

# Flat list of hashes, no usernames
graphcat -potfile hashcat.potfile -hashfile hashes_only.txt -format 1

# Air-gapped box: no outbound requests at all
graphcat -potfile hashcat.potfile -hashfile dump.ntds -offline

# Standalone PNGs to paste into the engagement report
graphcat -potfile hashcat.potfile -hashfile dump.ntds \
         -export-charts -output-dir ./charts
```

---

## How it behaves

**PDF engines.** `fpdf` is pure Python and always available. `weasyprint` renders
the HTML/CSS template but needs Pango and Cairo. `auto` picks WeasyPrint when it
is importable and silently falls back to `fpdf` otherwise, so a report is always
produced. The chosen engine is printed on every run.

**Unicode.** The fpdf engine embeds DejaVu Sans, which ships with matplotlib, so
passwords containing accents, Greek or Cyrillic render correctly with no extra
font to install. Characters outside its coverage — CJK, most emoji — become a
placeholder rather than aborting the report.

**Keyboard patterns.** At startup the tool fetches ~9,600 patterns from
[SecLists](https://github.com/danielmiessler/SecLists) over HTTPS using the
standard library. With no connectivity it says so and continues with a small
built-in list; nothing else in the report changes. Use `-offline` to skip the
request entirely — worth doing on an isolated engagement box.

**Performance.** zxcvbn scoring dominates the runtime, at roughly a millisecond
per password. A dump with 50,000 cracked hashes spends about a minute in that
phase. The progress bar tracks it.

---

## Reading the analyses

### Uniqueness counts variations, not just distinct strings

Counting distinct strings flatters a password set. `nacional12` and `nacional13`
are two different strings, but they are one idea — crack either and a single
mangling rule hands you the other. Reporting them as two unique passwords
overstates how much work an attacker actually faces.

So accounts land in three buckets instead of two:

| Bucket | Meaning |
| --- | --- |
| **Unique** | A distinct password whose alphabetic root nobody else shares |
| **Variation of another** | A distinct password sharing its root with another password in the set |
| **Exact duplicate** | The same string as another account, character for character |

The root is the password reduced to its letters (`Nacional2024!` → `nacional`),
so the three buckets always add up to the number of cracked accounts. The report
states both figures — naive distinct-string diversity and effective diversity
once variations are folded in — and lists the roots with the most variants, which
is where a targeted rule would pay off most.

Passwords with fewer than three letters (pure digits, symbol soup) have no
meaningful root. They are never grouped as variations and count as unique unless
they are exact duplicates.

### Basewords and number patterns are separate tables

Basewords stay alphabetic, and digit runs get their own **Top 10 Number
Patterns** table. Merging them would let a handful of years crowd the real
basewords out of a ten-row table, and the two answer different questions: a
baseword tells you which wordlist to feed the next run, while a digit pattern
tells you which rule to append. Both are worth having; neither belongs in the
other's list.

Number patterns count runs of two or more digits, so single stray digits do not
drown the signal. Expect overlap with Temporal Patterns — a year is both — but
they are different lenses: Temporal reads years and months as dates, while this
one is simply what gets appended most often.

### `$HEX[...]` potfile entries are decoded

hashcat writes `$HEX[436f6e7472617365f1613130]` instead of the cleartext whenever
a password contains a colon, a newline, or bytes that are not valid UTF-8 — very
common with accented characters from cp1252 wordlists.

Those entries are decoded before anything is measured. It matters more than it
looks: left wrapped, that example counts as **26 characters** long with the mask
`$UUU$dddldlddddddddddlddddddd$` and contributes `HEX` as a baseword, when the
password is really the 12-character `Contraseña10`. Decoding is attempted as
UTF-8, then cp1252, then latin-1. The run reports how many entries were decoded.

---

## Handling sensitive data

The resulting PDF contains real cleartext passwords: the Top 10, the basewords,
and indirectly the masks.

- The bundled `.gitignore` blocks `*.pot`, `*.ntds`, `graphcat_*.pdf` and `*.png`
  so an engagement artifact cannot slip into a commit by accident.
- Write reports outside the repository tree — point `-output-dir` at the
  engagement folder — and delete them when the engagement closes.
- Run `git status` before pushing.

---

## Dependencies and supply chain

The default install pulls 15 third-party packages, down from 31. None of them
load external system libraries, and no non-stdlib code touches the network. Versions are pinned with SHA-256 hashes in
[`requirements.lock`](requirements.lock).

[`DEPENDENCIES.md`](DEPENDENCIES.md) records the full audit: `pip-audit` results,
provenance for every package, a typosquatting check, and a source review of
`zxcvbn-python` — the only dependency shipped as a source distribution, and so the
only one that executes code at install time. It also lists the commands to
reproduce all of it yourself.

---

## Troubleshooting

**`cannot load library 'libgobject-2.0-0'`** — Only reachable via
`-pdf-engine weasyprint`. Either install the system libraries listed under
*Optional: the WeasyPrint engine*, or drop the flag and use the default engine.

**`[!] No entries in potfile. Exiting.`** — The potfile is empty or in an
unexpected format. Add `-john` if it came from John the Ripper.

**`[!] No cracked users. Exiting.`** — No hash from `-hashfile` appears in the
potfile. Usually a wrong `-format`: check the hash file really is a secretsdump
dump if you passed `-format 3`.

**No history or temporal section in the PDF** — Working as intended; those
sections are skipped when there is no data. History needs the `_history` lines,
which `secretsdump.py` only emits with `-history`.

**`[!] Could not download the SecLists list`** — No connectivity. The report is
still generated using the built-in pattern list. Pass `-offline` to skip the
attempt.

---

## Credits and license

Original work: [graphcat](https://github.com/Orange-Cyberdefense/graphcat) by
Orange Cyberdefense (zblurx). This repository is a fork with additional analyses.

Released under the MIT license — see [LICENSE](LICENSE). The default PDF engine,
`fpdf2`, is LGPL-3.0-only and is installed as a separate package; see the note at
the end of [DEPENDENCIES.md](DEPENDENCIES.md).
