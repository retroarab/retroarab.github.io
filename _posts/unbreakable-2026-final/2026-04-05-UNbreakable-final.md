---
title: "UNbreakable 2026 Final Write-Ups"
date: 2026-04-09 12:00:00 +0300
tags: [CTF, UNbreakable2026]
categories: [CTF, Writeups]
---

## Overview

This post covers two web challenges from **UNbreakable 2026 Final** that stood out because the intended path relied on subtle server-side logic mistakes rather than brute force or straightforward input fuzzing.

---

## 1. farenheit — Web

**Category:** Web · **Vulnerability:** Business Logic Flaw / Validation-Persistence Desync

### Summary

The application sells music stems using a credits system. The flag is embedded in the **master** version of the premium track `Aurora Afterhours`, but the listed price is far above the starting balance. The intended solve was not to tamper with credits directly, but to exploit a mismatch between how `/api/cart/add` calculates price and how cart rows are actually inserted into the database.

### Solution

1. Created an account and inspected the source code.
2. Searched for `FLAG` and found that the flag is stored inside the `master_text` of the `Aurora Afterhours` record.
3. That stem costs **750000** credits, while a new account starts with only **650**, so buying it normally is impossible.
![alt text](/assets/img/posts/unbreakable2026/farenheit/image.png)
4. My first idea was to look for a direct credit manipulation bug, but credits are updated server-side through strict transaction logic, so that path was a dead end.
5. The interesting part is in `/api/cart/add`:
   - `normalizeFlag()` only accepts `true`, `1`, `"1"`, or `"true"`, so there is no loose-comparison trick here.
   - The server computes the charge per item using the incoming `preview_only` value.
   - But `insertRows()` builds the SQL column list from **only the first row** in the batch.
![alt text](/assets/img/posts/unbreakable2026/farenheit/image-1.png)
![alt text](/assets/img/posts/unbreakable2026/farenheit/image-2.png)
6. This creates a desync: a later item can influence pricing with `preview_only: true`, while that field is silently omitted from the actual database insert if the **first** item did not include `preview_only`.
7. I sent a batched add-to-cart request like this:

```json
{
  "items": [
    {
      "stem_id": "1f27e8910b87a2c4"
    },
    {
      "stem_id": "e2c1f7b6d94a30ae",
      "preview_only": true
    }
  ]
}
```

8. The result:
   - The cheap first item is charged normally.
   - The expensive `Aurora Afterhours` item is validated as a **preview**, so it adds **0** to the total price.
   - During insertion, the `preview_only` column is omitted for every row because the first item did not have that field.
   - SQLite then applies the default value `0`, meaning both rows are stored as **full master** items.
9. After checkout, the application delivered `aurora-afterhours-master.txt` instead of the preview file.
10. That master file contained the flag.

---

## 2. speakeasy — Web

**Category:** Web · **Vulnerability:** Protobuf Schema Confusion / Signed Semantic Mismatch

### Summary

The challenge issues an HMAC-signed ticket at the front door, then verifies the same signed bytes at the cellar entrance. The bug is that the front door and the cellar interpret field `4` using **different protobuf schemas**. This allows attacker-controlled data to remain fully signed while being reinterpreted as authorization metadata later.

### Solution

1. Reviewed the two relevant paths:
   - `/api/knock` signs a **TicketV1** structure.
   - `/api/enter` verifies the signature, then parses the same payload as **TicketV2**.
2. In `TicketV1`, field `4` is:

```proto
repeated uint32 tab = 4 [packed = true];
```

3. In `TicketV2`, field `4` is:

```proto
Proof proof = 4;
```

4. The cellar accepts access if either:
   - `status == "member"`, or
   - `proof.club == "speakeasy"` and `proof.knows_password == true`
5. So the objective is not to forge the HMAC, but to make the signed `tab` bytes decode as a valid `Proof` object when the cellar parses them.
6. I crafted `tab` so its packed bytes become:
   - `0x10 0x01` -> `knows_password = true`
   - `0x0a 0x09 "speakeasy"` -> `club = "speakeasy"`
7. The request to `/api/knock` looked like:

```json
{
  "name": "app",
  "whisper": "app",
  "tab": [16, 1, 10, 9, 115, 112, 101, 97, 107, 101, 97, 115, 121]
}
```

8. This returns a valid signed ticket such as:

```text
CgNhcHASA2FwcBoFZ3Vlc3QiDRABCglzcGVha2Vhc3k=.lpwnfT6m5RI1_ZSs8j9iyYdgW6Nl84eaKY-T_VPOa1Q=
```

9. Submitting that ticket to `/api/enter` passes verification and is interpreted by the cellar as:
   - `status = "guest"`
   - `proof.club = "speakeasy"`
   - `proof.knows_password = true`
10. Even though the real password is never known, the secondary authorization branch succeeds and the endpoint returns the flag.


![alt text](/assets/img/posts/unbreakable2026/speakeasy/image.png)
![alt text](/assets/img/posts/unbreakable2026/speakeasy/image-1.png)
![alt text](/assets/img/posts/unbreakable2026/speakeasy/image-2.png)
![alt text](/assets/img/posts/unbreakable2026/speakeasy/image-3.png)
![alt text](/assets/img/posts/unbreakable2026/speakeasy/image-4.png)