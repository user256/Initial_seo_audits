# SEO Parity & Consolidation Checker

A command-line tool to validate **SEO parity between JavaScript and non-JavaScript renders** of a website, with additional checks for URL consolidation and `robots.txt` compliance.  

It helps detect issues where search engines or users might see different content depending on rendering, URL variations, or misconfigured directives.

---

## Features

- **Render comparison**:  
  Fetches pages both with and without JavaScript (headless Chrome via Selenium) and compares:
  - `<title>`
  - `<meta name="description">`
  - `<link rel="canonical">` (HTML and HTTP header)
  - `<meta name="robots">`
  - `X-Robots-Tag` headers
  - `<h1>` count
  - Internal link sets (normalized parity check)

- **Robots.txt validation**:  
  - Retrieves `robots.txt`
  - Checks crawlability of discovered internal links for the given User-Agent

- **URL consolidation checks**:
  - **HTTP → HTTPS** redirection
  - **WWW vs non-WWW** canonicalization
  - **camelCase vs lowercase paths** (redirects, canonicals, or duplicates)

- **404 validation**:  
  Ensures custom error pages return a true HTTP 404 status.

- **Logging**:  
  - Results printed to console
  - Written to a logfile named from the tested domain and slug  
    (e.g. `seo_report_example.com_about.txt`)

---

# Setup (Recommended: Virtual Environment)

## Linux / macOS

1. **Install venv & pip if missing**  
   ```bash
   sudo apt update
   sudo apt install -y python3-venv python3-pip
   ```

2. **Create a virtual environment**  
   ```bash
   python3 -m venv seoenv
   source seoenv/bin/activate
   ```

3. **Upgrade pip and install dependencies**  
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

   > When finished working, you can exit the environment with:
   ```bash
   deactivate
   ```

---

## Running the Script

### Option 1: Activate the environment each session
Activate the venv:
```bash
source seoenv/bin/activate
```

Run the checker:
```bash
python runner.py --url https://whiskipedia.com --user-agent "paradise-crawler"
```

### Option 2: Run directly via venv Python
Without activating the environment:
```bash
# Use defaults (http://whiskipedia.com, UA "paradise-crawler")
./seoenv/bin/python runner.py

# Specify a custom site & UA
./seoenv/bin/python runner.py --url https://whiskipedia.com -A "MySEOScanner/1.0"
```

---

## Windows (PowerShell)

If your PowerShell blocks script activation, start the shell as Administrator and run:
   ```bash
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

1. **Install venv & pip if missing**  
   ```bash
   sudo apt update
   sudo apt install -y python3-venv python3-pip
   ```

2. **Create a virtual environment**  
   ```bash
   python -m venv audit_env
   .\audit_env\Scripts\Activate.ps1
   ```

3. **Upgrade pip and install dependencies**  
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

   > When finished working, you can exit the environment with:
   ```bash
   deactivate
   ```

Run the checker:
```bash
python runner.py --url https://whiskipedia.com --user-agent "paradise-crawler"
```

### Option 2: Run directly via venv Python
Without activating the environment:
```bash
# Use defaults (http://whiskipedia.com, UA "paradise-crawler")
  .\audit_env\Scripts\python.exe runner.py

# Specify a custom site & UA
  .\audit_env\Scripts\python.exe runner.py --url https://whiskipedia.com -A "MySEOScanner/1.0"
  .\audit_env\Scripts\python.exe runner.py --url https://dotesports.com -A "paradise-crawler"
```




---

### Arguments
- `--url`  
  Homepage URL to test. Defaults to `http://whiskipedia.com`
- `--user-agent` / `-A`  
  User-Agent string. Defaults to `paradise-crawler`
- `--max-links`  
  Cap on internal links to validate. Default: 120

### Examples

```bash
# Use custom URL and UA
python runner.py --url https://example.com --user-agent "MyBot/1.0"

# Test a URL with defaults
python runner.py --url https://example.com

# Run with all defaults (uses DEFAULT_URL and DEFAULT_UA)
python runner.py
```

---

## Output

1. **Render comparison (JS vs non-JS)**  
   Flags differences in title, description, canonical, robots directives, headers, and link parity.

2. **robots.txt**  
   Reports whether internal links are blocked.

3. **URL consolidation checks**  
   Shows whether HTTP→HTTPS and WWW/non-WWW variants consolidate properly.  
   Tests uppercase vs lowercase URL handling.  

4. **Custom 404 behavior**  
   Verifies correct 404 response.

5. **Internal link accessibility**  
   Checks sampled links for HTTP status and robots.txt disallow.

6. **Summary flags**  
   Highlights key SEO issues in a concise checklist.

---

## Example Logfile

Logs are appended to `seo_report_<domain>_<slug>.txt`.

Example:  
- URL tested: `https://example.com/about`  
- Logfile: `seo_report_example.com_about.txt`

---

## Notes

- Use consistent User-Agent to match crawler behavior.
- The tool **does not replace full SEO audits**, but helps surface common rendering and consolidation issues quickly.
- SPA-heavy pages may require longer wait times for JS rendering. Adjust sleep if needed.

---