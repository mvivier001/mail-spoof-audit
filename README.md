# 📬 Mail Spoof Audit

A fast CLI tool to audit **SPF, DMARC, DKIM** and identify **email spoofing risks** across multiple TLDs.

---

## 🚀 Features

- ✅ Check domain existence
- ✅ SPF validation
- ✅ DMARC analysis (with policy detection)
- ✅ DKIM presence check
- ✅ Multi-TLD scanning
- ✅ Spoofing risk detection
- ✅ Optional MX & PTR checks
- ✅ Multithreaded

---

## 📦 Installation

### With pipx (recommended)

```bash
pipx install git+https://github.com/yourname/mail-spoof-audit.git
```
---

## ⚙️ Usage

```bash
mail-spoof-audit <domain> [options]
```

---

## Example

```bash
mail-spoof-audit test --threads 10 
```

---

## 🧾 Output Example

Domain                    Ex SPF DMARC           DKIM Reason             Spoof
-------------------------------------------------------------------------------
test.com                  ✅  ✅  ✅ (reject)     ✅   -                     🔴
test.fr                   ✅  ✅  ❗ (none)       ❌   DMARC none            🟡
test.io                   ✅  ❌  ❌              ❌   no SPF                🟢
test.lu                   ❌  ❌  ❌              ❌   domain does not exist ❌

📝 Conclusion : The following domains could be spoof :
👉 test.fr, test.io

---

## 🧠 Spoofing Logic

| Condition                        | Result | Risk   |
| -------------------------------- | ------ | ------ |
| Domain does not exist            | ❌     | None   |
| No SPF record                    | 🟢     | High   |
| SPF but no DMARC                 | 🟡     | Medium |
| DMARC policy = none              | 🟡     | Medium |
| DMARC policy = quarantine/reject | 🔴     | None   |

---

## ⚠️  Disclaimer

This tool is intended for:

* Security research
* Defensive audits
* Educational purposes

Do not use it against systems you do not own or have explicit permission to test.


