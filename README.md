# SME Security Scanner

**A free, plain-English security check for your business domain, which you run on your own computer.**

Enter your domain (for example `example.com`) and get a security score, a list of what to fix, and a PDF report you can
hand to your IT provider. There is no account to create and nothing is attacked: the scan only looks at information your
domain already makes public.

Built for small and medium businesses in Kenya, and useful anywhere. It focuses on the everyday weaknesses that cause
real incidents: misconfiguration, exposed services and weak access controls.

> **Hosted version:** not available yet. For now you run it yourself (about 5 minutes, steps below).
> Click **Watch** on this repository (choose *Custom > Releases*, or *All activity*) to be notified if a hosted version is added.

---

## Quick start

You need an internet connection and **Python 3.10 or newer** ([download Python](https://www.python.org/downloads/); on Windows, tick *"Add Python to PATH"* during install).

**1. Download the project.** Click the green **Code** button on this page, then **Download ZIP**, and unzip it. (If you use Git: `git clone` the repository instead.)

**2. Open a terminal in the project folder.**
- **Windows:** open the folder in File Explorer, click the address bar, type `cmd` and press Enter.
- **Mac:** right-click the folder and choose *New Terminal at Folder*.
- **Linux:** open a terminal and `cd` into the folder.

**3. Install and start it.**

Windows:
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Mac / Linux:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

**4. Open the scanner** in your browser at **http://127.0.0.1:5000**

**5. Enter your domain** (such as `example.com`, without `https://` or page paths) and click **Scan domain**. A scan usually takes under a minute.

**6. Click "Download PDF report"** to save the report.

To stop the scanner, go back to the terminal and press `Ctrl + C`. Next time, you only need to repeat steps 2, then the *activate* line and the *python app.py* line from step 3.

<details>
<summary>Prefer Docker?</summary>

```
docker build -t sme-scanner .
docker run -p 8000:8000 sme-scanner
```
Then open http://localhost:8000
</details>

### If something goes wrong

| Problem | Try this |
|---|---|
| `python` is not recognised | Reinstall Python and tick *Add Python to PATH*, or use `py` (Windows) or `python3` (Mac/Linux) |
| `pip install` fails | Update pip: `python -m pip install --upgrade pip`, then retry |
| Page won't open | Make sure the terminal still shows the app running, and use exactly `http://127.0.0.1:5000` |
| Subdomain list is empty or says unavailable | The free certificate-log service (crt.sh) was busy. Wait a minute and scan again |
| Every domain shows "does not exist" | Check your internet connection, VPN or firewall. The scanner needs to look up public DNS |
| Report link says "expired" | Reports are kept in memory for about an hour and are lost when you stop the app. Scan again and download the PDF straight away |

---

## What you get

- A **score out of 100** and a **grade from A to F**
- Findings sorted by severity, each with a **plain-English explanation and a suggested fix**
- A **PDF report** with an executive summary, a short list of priority actions, full details, and appendices listing the technology and subdomains found

### What the severity labels mean

| Label | Meaning | What to do |
|---|---|---|
| **Critical** | Serious and urgent, such as an expired certificate or an open remote-access port | Fix immediately |
| **High** | A real weakness attackers commonly use | Fix this week |
| **Medium** | Worth fixing; makes you noticeably safer | Plan it in |
| **Low** | Good-practice improvement | Fix when convenient |
| **Info** | Something to be aware of or check; not necessarily a problem | Read and decide |
| **Pass** | You're doing this right | Nothing |

### What it checks

| Area | In plain terms |
|---|---|
| **DNS** | Is your domain set up reliably, and can you control which companies may issue certificates for it (CAA)? |
| **DNSSEC** | Is your domain protected against forged DNS answers? |
| **SSL/TLS** | Is your website's padlock valid, strong and up to date? Are outdated, weak protocols switched off? |
| **Certificate expiry** | How long until your certificate expires? |
| **HTTP headers** | Does your website tell browsers to apply protections (HSTS, CSP, clickjacking, cookie flags)? |
| **Email (SPF, DKIM, DMARC)** | Can someone send fake email pretending to be you? |
| **Subdomains** | Which hostnames of yours are publicly visible, and are any forgotten, test or admin systems? Are any left pointing at services you no longer own (a takeover risk)? |
| **Exposed services** | Are risky services such as remote desktop, databases or FTP reachable from the internet? *(Optional port check, see below.)* |
| **Technology stack** | Which website platform, server and CDN are you running? |
| **Security contact** | Do you publish a `security.txt` so researchers can report problems to you? |
| **Privacy (preview)** | Is a privacy-notice link visible on your homepage? |

## The optional port check

By default the scan is entirely passive. If you tick **Advanced: open-port check**, the scanner also makes a single
connection attempt to 13 well-known ports (such as remote desktop, databases and FTP) to see whether they are open to the internet.
It sends no exploits, no passwords and no data.

**Only use it on domains you own or have written permission to test.** You must tick a box confirming this before it will run.
Because you run the tool yourself, these connections come from **your** computer and internet connection.

If the site is behind a CDN or managed platform (Cloudflare, Shopify and similar), the result describes their servers, not yours,
and the report says so.

## Is it safe to scan a domain?

Yes. "Passive" means the scanner only uses:

- public DNS records,
- public certificate-transparency logs (the open record of every certificate ever issued for a domain),
- a normal secure connection to the website, like a browser makes, and
- ordinary page requests.

It never guesses passwords, tries to break in, or tests for exploitable bugs. You can run the default scan on any domain,
but please only use the port check on systems you're authorised to test.

## Your privacy

- The scanner runs **on your own computer**. There is no account, and nothing is sent to the project maintainer.
- To do its job it contacts only public services: DNS resolvers (Cloudflare and Google), the crt.sh certificate-log service, and the domain you are scanning.
- Results are held in memory while the app is running (up to an hour) and are not written to a database. The PDF is saved only where *you* save it.
- A limit of **10 scans per hour** applies, to prevent accidental overload.

## Limits you should know about

This tool is a useful first check, **not** a full security audit.

- It can't see inside your network, applications, cloud accounts, laptops or phones.
- It can't tell whether your staff use strong passwords or multi-factor authentication.
- **DKIM** keys can have any name, so the scanner tries common ones. "Not found" is a hint to check, not proof you have no DKIM.
- Some findings may not apply to you. If your site is hosted by a platform like Shopify or Wix, the platform controls many settings and the report notes this.
- The privacy check is an automated hint only. It does **not** assess compliance with Kenya's Data Protection Act, 2019. For that, see guidance from the **Office of the Data Protection Commissioner (ODPC)**.
- Automated tools produce occasional false positives. Review findings with your IT provider before acting.

A good score is not a guarantee of security, and it isn't a substitute for a penetration test or a compliance audit.

## Frequently asked questions

**Do I need to be technical?** You need to be comfortable copying a few commands into a terminal. After that, every finding says what it means and how to fix it. Send the PDF to your web or IT provider if you're not sure how to apply a fix.

**My domain says "does not exist" or isn't graded.** Check the spelling and that the domain is registered and active. A domain that doesn't resolve can't be assessed.

**Why is my score lower than I expected?** One or two serious findings (Critical/High) weigh heavily. Many small Low items cost very little, so work from the top of the list down.

**I fixed something but the report still shows it.** DNS changes can take minutes to hours to spread. Wait, then scan again.

**Can I scan a domain that isn't mine?** The passive scan only uses public information. The port check needs your authorisation to test the domain.

**Does it work for non-Kenyan domains?** Yes, any public domain. The privacy and guidance notes reference Kenyan law and bodies.

**Will there be a hosted version?** Possibly. Watch this repository to hear about it.

## Found a bug or want a feature?

Please open an **Issue** on this repository. If a finding looks wrong, include the domain (if you're happy to share it), what the report said, and what you expected. That makes it much easier to fix.

If you believe you've found a security problem in the scanner itself, please report it privately to the maintainer rather than posting it publicly.

