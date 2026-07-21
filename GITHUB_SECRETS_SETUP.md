# GitHub Actions — Secrets (jangan bocor)

Jangan commit `.env`. Semua credential lewat **GitHub Secrets**.

## 1. Buat secrets

Repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Secret name | Isi | Wajib |
|-------------|-----|-------|
| `ROUTER9_URL` | `http://47.237.201.60:20128` (URL publik 9router) | ✅ |
| `ROUTER9_PASS` | password admin 9router | ✅ |
| `GMAIL_USER` | Gmail catch-all (contoh `maximus.sale1@gmail.com`) | ✅ |
| `GMAIL_APP_PASSWORD` | App Password 16 char (boleh ada spasi) | ✅ |
| `GMAIL_DOMAINS` | domain alias, contoh `0xsassy.my.id` | ✅ |
| `ACCOUNT_PASSWORD` | password akun Grok baru (≥16 char) | ✅ |
| `PROXIES` | residential proxy (lihat format) | ✅ |
| `SCTG_API_KEY` | key sctg.xyz | ✅ |
| `SCTG_TIMEOUT` | optional, default `45` | ❌ |
| `SCTG_RETRIES` | optional, default `3` | ❌ |
| `CHROME_BIN` | optional | ❌ |

### Format `PROXIES` (residential WAJIB di GHA)

Satu:
```
http://username:password@host:port
```

Pool (comma):
```
http://u1:p1@host1:port1,http://u2:p2@host2:port2
```

**Jangan** pakai datacenter murni / kosong. Runner GHA = Azure DC → Cloudflare block tanpa residential.

## 2. File yang BOLEH di-commit

- `grok-signup-playwright-gmail-headless.py`
- `turnstilePatch/`
- `requirements.txt`
- `.github/workflows/xai-auto.yml`
- `.env.example` (template kosong)
- `.gitignore` (harus ignore `.env`, `sso.txt`, `*.log`)

## 3. File yang JANGAN di-commit

```
.env
.env.*
sso.txt
*.log
__pycache__/
.venv/
```

Cek:
```bash
git status
# pastikan .env TIDAK muncul
```

## 4. Push & run

```bash
git add .github/workflows/xai-auto.yml grok-signup-playwright-gmail-headless.py turnstilePatch requirements.txt .gitignore .env.example
git commit -m "Add GHA xai auto signup (secrets-only)"
git push origin main
```

GitHub → **Actions** → **xai auto** → **Run workflow**

| Input | Saran first run |
|-------|-----------------|
| max_accounts_per_job | `1` |
| headless | true |
| auto_add | true |
| delay_seconds | 12 |

Matrix `job_id: [1..5]` → 5 runner paralel.  
Total akun ≈ `max_accounts_per_job × 5`.

First run: set `max_accounts_per_job=1` → total 5 akun (1 per job).

## 5. Keamanan runtime

Workflow:
1. Tulis `.env` di runner (chmod 600)
2. Jalankan script
3. Redact log artifact
4. `shred` / hapus `.env`
5. Wipe temp `grok-pw-*`

Artifact: `run-jobN.redacted.log` + `sso.txt` (email/password akun — treat as secret, retention 7 hari).

## 6. Troubleshooting

| Error | Arti |
|-------|------|
| Missing secret X | Belum diisi di Settings → Secrets |
| Proxy preflight FAILED | PROXIES mati / 402 / bukan residential |
| Blocked due to abusive traffic | IP DC (tanpa proxy / proxy jelek) |
| 9Router unreachable | ROUTER9_URL tidak publik dari internet |
| SCTG fail | cek saldo / key |

## 7. Catatan jujur

- GHA **bukan** pengganti residential proxy.
- PC headless tetap path paling stabil.
- Matrix 5× paralel bisa rate-limit 9router device-code (`slow_down`) — turunkan parallel / naikkan delay.
