# checklist

✅ Phase 1 – Planning
1. Spider the application logging all GET and POST requests. Ensure that credentialed spidering is performed when approach is gray box.

Objective:
Enumerate all endpoints and parameters (including hidden or dynamically loaded ones) for attack surface mapping.

Steps:

    Log in to the application with test credentials.

    Launch Burp Suite and enable “Spider” or “Crawl and Audit” in the Target tab.

    Use Burp's “Logged-in session” handling via macros or session rules.

    Browse all application pages manually post-login to ensure authenticated coverage.

    Review the Site Map to verify all GET and POST requests are captured.

Pass Criteria:
All reachable authenticated endpoints and their parameters are logged.

Fail Criteria:
Endpoints missed due to improper session handling, JS-heavy routing, or incomplete spidering.

Screenshots:

    Site Map with full GET/POST request tree

    Session-handling configuration

    Example request with valid session cookie

2. Fingerprint the application and server stack (platforms, plugins, libraries, and their versions)

Objective:
Identify backend technologies and versions for attack surface correlation and vulnerability lookup.

Steps:

    Use Wappalyzer or BuiltWith browser plugin for basic fingerprinting.

    Use Burp’s passive scan headers (e.g., X-Powered-By, Server) to detect backend.

    Run whatweb, nmap -sV, or httprint against the application host.

    If JavaScript libraries are present, analyze them for versioning via JS file URLs or hashes.

Pass Criteria:
Tech stack components (e.g., Apache 2.4.7, PHP 5.6.4, AngularJS v1.6.1) are identified.

Fail Criteria:
Fingerprinting fails or returns generic/obfuscated responses.

Screenshots:

    whatweb or nmap results

    Response headers in Burp

    JS library URLs (with versions)

3. Research custom test cases related to enumerated application/server stack and append to checklist

Objective:
Build targeted attack test cases using the CVEs or known vulnerabilities in discovered components.

Steps:

    Search CVEs using the versioned software stack via:

        CVE Details

        NVD

        Exploit-DB

        GitHub advisories

    Note potential exploits or bypasses (e.g., Apache 2.4.7 path traversal, outdated jQuery XSS).

    Add manual test items (e.g., XXE, insecure deserialization) to upcoming checklist phases.

Pass Criteria:
At least one custom test case mapped to discovered tech.

Fail Criteria:
No actionable vulnerabilities found or test cases remain generic.

Screenshots:

    CVE listings or PoC

    Checklist entries updated with component-specific tests

4. Map business-critical functionalities for maximum coverage. Eliminate potentially dangerous functionalities to be removed from scanning.

Objective:
Identify functional paths crucial to business and isolate areas requiring manual or limited testing.

Steps:

    Review all features post-login (export, reports, payments, user management).

    Document workflows like “Export to Excel,” “User management,” etc.

    Categorize features:

        Business-critical

        Sensitive (e.g., export, payments)

        Low-risk

    Mark sensitive ones for manual testing only (no active scanner).

Pass Criteria:
All core functionalities mapped and scanning exclusions defined.

Fail Criteria:
Important features missed or over-tested (e.g., exporting files with active scanner).

Screenshots:

    Functional map or flowchart

    Scanner configuration showing exclusions

    Feature walkthrough (e.g., export functionality)

✅ Phase 2 – Automated Testing

Each test below includes:

    Test Objective

    Step-by-step Procedure

    Pass/Fail Criteria

    Screenshots to Capture

🔹 1. If Netsparker/Nessus does not work on the application in scope, use Burp active scanner to walk through the application. Configure authentication for gray box testing (Use Burp Configuration guidelines)

Objective:
Ensure active scanning is configured with proper session handling and walks through authenticated sections of the app.

Steps:

    Log in to the application using the provided credentials.

    Configure session handling in Burp Suite using:

        Macros (to re-login)

        Session rules (to maintain token)

    Manually browse key application areas.

    Right-click in Target > Scan or use Burp Scanner on selected items.

    Ensure authenticated pages are within the scope and monitored.

Pass Criteria:
Burp successfully crawls and audits authenticated areas.

Fail Criteria:
Scanner fails to authenticate or scans only unauthenticated content.

Screenshots:

    Session handling rule

    Macro recording

    Scan queue showing authenticated URLs

🔹 2. For applications with multiple roles, ensure that scanning is performed for at least one role per each access level.

Objective:
Verify role-based access areas are covered in scanning.

Steps:

    Identify all provided user roles (e.g., admin, standard user).

    Repeat login and session handling setup for each role.

    Browse the application with each role to capture the sitemap.

    Run active scan for each role separately.

Pass Criteria:
Each user role has its own scan coverage, and role-specific endpoints are reached.

Fail Criteria:
Only one role is scanned; role segregation coverage missed.

Screenshots:

    Role-based login sessions

    Scan scope per role

    Site map comparison across roles

🔹 3. Run testssl.sh and sslscan on the host IP / Web address

Objective:
Identify SSL/TLS-related weaknesses (e.g., weak ciphers, TLS 1.0/1.1, invalid certs).

Steps:

    Use terminal and run:

testssl.sh https://target.com

and

    sslscan target.com

    Review output for:

        Protocol support (SSLv2/SSLv3/TLS1.0/TLS1.2/1.3)

        Cipher strength (key length < 128 bits)

        Certificate issues (expired, self-signed)

Pass Criteria:
No weak ciphers or deprecated protocols; valid certificate.

Fail Criteria:
Support for SSLv2/3, TLS 1.0/1.1, weak ciphers (e.g., RC4), or cert issues.

Screenshots:

    Output from testssl.sh

    Output from sslscan

    Highlight of weak protocol/cipher if any

🔹 4. Use DirBuster or dirb with platform-specific wordlists to discover application directories and files.

Objective:
Uncover hidden or unlinked directories/files not exposed in the UI.

Steps:

    Identify tech stack (PHP, ASP.NET, Node.js, etc.).

    Run:

dirb https://target.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

or

    dirbuster & select relevant list

    Use extensions like .php, .aspx, .jsp depending on backend.

    Analyze discovered resources.

Pass Criteria:
All accessible paths are discovered or application responds with 403/404 appropriately.

Fail Criteria:
Sensitive or misconfigured paths (e.g., /admin/, /backup/, /logs/) are exposed.

Screenshots:

    DirBuster/dirb result showing discovered paths

    Response for discovered sensitive file

🔹 5. Run Nikto on the host IP / Web address

Objective:
Identify web server misconfigurations and known insecure files.

Steps:

    Launch:

    nikto -h https://target.com

    Wait for the scan to complete.

    Review results:

        Deprecated HTTP methods

        Insecure scripts (e.g., test.cgi, phpinfo.php)

        Directory listings

        Default files (e.g., /admin, /cgi-bin/)

Pass Criteria:
No high/medium-risk issues found, default files removed.

Fail Criteria:
Exposed debug/info files, insecure headers, outdated server versions.

Screenshots:

    Nikto scan output

    Evidence of vulnerable/default file exposed
