# Dependency audit

Last reviewed: **2026-08-26**, against the versions pinned in
[`requirements.lock`](requirements.lock).

This tool processes cleartext credentials, so its dependency tree is deliberately
small and every package in it is accounted for below.

## Attack surface was cut, not just audited

The original tool rendered its PDF with WeasyPrint and downloaded a wordlist with
`requests`. Both were replaced:

- **WeasyPrint → fpdf2.** WeasyPrint binds to Pango, Cairo and GDK-PixBuf through
  cffi. It is now optional.
- **requests → `urllib.request`.** The standard library already does what was
  needed, removing `requests`, `urllib3`, `certifi`, `idna` and
  `charset-normalizer`.

Net effect on a default install: **31 third-party packages down to 15.**

| | Before | After |
| --- | --- | --- |
| Third-party packages installed | 31 | 15 |
| Packages that `dlopen` external system libraries | 1 (`weasyprint`) | 0 |
| Non-stdlib code that touches the network | `requests`, `urllib3` | none |

The remaining compiled packages (`numpy`, `pillow`, `contourpy`, `kiwisolver`,
`fonttools`) ship self-contained manylinux/macOS/Windows wheels; they do not load
anything from the host beyond libc.

## Direct dependencies

| Package | Upstream | License | Why it is here |
| --- | --- | --- | --- |
| `matplotlib` | matplotlib.org | PSF-based | Renders every chart |
| `fpdf2` | [py-pdf/fpdf2](https://github.com/py-pdf/fpdf2) | LGPL-3.0-only | Default PDF engine, pure Python |
| `zxcvbn-python` | [dwolfhub/zxcvbn-python](https://github.com/dwolfhub/zxcvbn-python) | MIT | Password strength scoring |
| `tqdm` | [tqdm/tqdm](https://github.com/tqdm/tqdm) | MPL-2.0 / MIT | Progress bars |

Optional, only with `pip install "graphcat-extended[weasyprint]"`:

| Package | Upstream | License | Why it is here |
| --- | --- | --- | --- |
| `weasyprint` | [Kozea/WeasyPrint](https://weasyprint.org/) | BSD-3-Clause | Alternative HTML/CSS PDF engine |
| `Jinja2` | [pallets/jinja](https://github.com/pallets/jinja) | BSD-3-Clause | Fills the HTML template for that engine |

Transitive packages are the standard matplotlib and fpdf2 sets: `numpy`,
`pillow`, `fonttools`, `contourpy`, `kiwisolver`, `cycler`, `pyparsing`,
`python-dateutil`, `six`, `packaging`, `defusedxml`.

## What was checked

**1. Known vulnerabilities.** `pip-audit` against the OSV database:

```
$ pip-audit -r <pinned core set>
No known vulnerabilities found
```

Audited on 2026-08-26 across all 15 pinned packages.

**2. Typosquatting.** Every package resolves to its canonical upstream repository,
and download volumes match mainstream projects (numpy ~1.18B/month, tqdm
~675M/month, matplotlib ~242M/month). The name worth checking is
`zxcvbn-python`: it is the legitimate Python port of Dropbox's zxcvbn by Daniel
Wolf, not a squat on the shorter `zxcvbn` name. Note the distribution is
`zxcvbn-python` while the import is `zxcvbn`.

**3. Install-time code execution.** Wheels do not execute code when installed;
source distributions run `setup.py`. Of the pinned set, **`zxcvbn-python` is the
only sdist**, so it was reviewed directly:

- `setup.py` contains nothing but `setuptools.setup()` metadata — no network
  access, no `exec`, no subprocesses.
- Across the package, the only imports are standard library: `argparse`,
  `getpass`, `json`, `re`, `sys`, `warnings`, `datetime`, `decimal`, `gettext`,
  `math`.
- Grepping for `eval(`, `exec(`, `__import__`, `subprocess`, `os.system`,
  `socket`, `urlopen`, `b64decode`, `pickle` and `marshal` returns nothing.
- The 790 KB `frequency_lists.py` is pure data — word frequency lists, no logic.

**4. Reproducibility.** `requirements.lock` pins exact versions and lists the
SHA-256 of every artifact published for them. Installing with
`--require-hashes` turns a tampered or substituted package into a hard install
failure.

## Verifying it yourself

Do not take the table above on trust — reproduce it:

```bash
pip install pip-audit
pip-audit                                  # known CVEs
pip download --no-deps --no-binary :all: zxcvbn-python -d /tmp/z
tar tzf /tmp/z/zxcvbn-python-*.tar.gz      # confirm it is the only sdist
pip install --require-hashes -r requirements.lock   # hash-verified install
```

## Scope and limits

This is a static review plus a known-vulnerability scan of specific pinned
versions. It shows no signs of malicious behaviour and no known CVEs — it is not
a proof that none exists, and it says nothing about versions other than those
pinned. Re-run `pip-audit` whenever you bump a dependency.

## A note on fpdf2's license

`fpdf2` is LGPL-3.0-only, while this project is MIT. Importing an LGPL library
does not affect the license of this code, and pip installs `fpdf2` as a separate
package rather than bundling it, so redistributing this repository under MIT is
fine. If your engagement forbids LGPL components outright, install with the
WeasyPrint extra (BSD-3-Clause) and run `-pdf-engine weasyprint`.
