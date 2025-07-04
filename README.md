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

✅ Phase 3 – Manual Testing: Information Gathering
🔹 1. Conduct Search Engine Discovery Reconnaissance for Information Leakage

Objective:
Identify exposed application data or endpoints via search engines.

Steps:

    Use Google Dorks:

        site:target.com

        site:target.com inurl:admin

        site:target.com filetype:pdf

        site:target.com intitle:index.of

    Repeat with Bing, Yandex.

    Review results for sensitive endpoints or documents.

Pass Criteria:
No sensitive data or unlinked pages appear in search results.

Fail Criteria:
Exposed endpoints, credentials, debug files, internal documentation found via search.

Screenshots:

    Search results showing sensitive endpoints or file exposure.

🔹 2. Attempt to identify hidden features (e.g. debug/admin params or links)

Objective:
Reveal parameters or paths not accessible via UI.

Steps:

    Use tools like ParamMiner, Arjun, or Burp Param Search.

    Manually brute-force parameters in URLs like:

        ?debug=true

        ?admin=1

        ?test=1

    Monitor for behavioral changes or verbose error messages.

Pass Criteria:
No changes in behavior when injecting suspicious parameters.

Fail Criteria:
Access to hidden features, debug info, or additional UI elements.

Screenshots:

    Parameter discovery tool output

    Response showing hidden parameter effect

🔹 3. Verify if sensitive info (e.g., passwords) sent via GET

Objective:
Check for password leakage in URL/query string.

Steps:

    Interact with login/reset forms.

    Inspect Burp HTTP history and URL bar for:

        ?password=

        ?token=

    Analyze browser history and proxy logs.

Pass Criteria:
Sensitive info not passed via GET method.

Fail Criteria:
Passwords, reset tokens, OTPs visible in URLs or referrers.

Screenshots:

    GET request with sensitive data

    Browser URL with exposed data

🔹 4. Identify potentially dangerous functionalities (e.g. file uploads)

Objective:
Discover upload points that could allow malicious file execution.

Steps:

    Look for upload buttons, forms, profile picture areas.

    Try uploading:

        .php, .jsp, .aspx, .exe, .sh, .svg

        EICAR file (test signature)

    Bypass content-type and extension filters using Burp.

Pass Criteria:
Upload restricted to specific MIME types and extensions.

Fail Criteria:
Executable files are accepted or bypass possible.

Screenshots:

    Upload form

    Response accepting/rejecting dangerous files

🔹 5. Identify CMS/Framework in use (e.g., WordPress, Drupal)

Objective:
Identify underlying tech to correlate known CVEs.

Steps:

    Use Wappalyzer, BuiltWith, or WhatWeb:

    whatweb target.com

    Inspect headers and responses for fingerprints:

        X-Powered-By

        CMS-specific paths (e.g. /wp-admin, /drupal)

Pass Criteria:
CMS/framework version is current and secure.

Fail Criteria:
Outdated CMS or plugins identified.

Screenshots:

    Tool output showing CMS

    Headers showing tech stack

🔹 6. Identify interesting comments in application source code

Objective:
Find developer notes or API keys exposed in comments.

Steps:

    Open page source (Ctrl+U) and search:

        <!--

        TODO, FIXME, API_KEY, SECRET

    Use Burp or browser extension to extract comments from all loaded pages.

Pass Criteria:
Only generic HTML comments present.

Fail Criteria:
Sensitive info, internal IPs, endpoints, credentials in comments.

Screenshots:

    HTML code with sensitive comments

    Developer comments disclosing internals

🔹 7. Review web server metafiles (robots.txt, sitemap.xml)

Objective:
Find disallowed or sensitive paths excluded from crawlers.

Steps:

    Navigate to:

        https://target.com/robots.txt

        https://target.com/sitemap.xml

    Parse disallowed directories and endpoints.

Pass Criteria:
No sensitive paths listed in robots.txt.

Fail Criteria:
Sensitive admin/debug paths exposed via these files.

Screenshots:

    Contents of robots.txt

    Entries in sitemap.xml exposing internal pages

🔹 8. Check for GitHub repositories related to application/framework

Objective:
Find public repos that might expose issues, keys, or documentation.

Steps:

    Search:

        site:github.com target.com

        Organization or developer handle

    Review open/closed issues for known bugs.

    Clone and search repos for secrets using:

    git-secrets --scan

Pass Criteria:
No public repos tied to production application.

Fail Criteria:
Hardcoded secrets, endpoint leaks, exposed source code found.

Screenshots:

    Relevant GitHub repo/issues

    Secret exposure in source code

🔹 9. Identify business use and define logic tests (linked to Phase 11)

Objective:
Understand key business workflows to test for abuse (e.g., price manipulation).

Steps:

    Read through UI and test user flows like:

        Checkout

        Discounts

        Profile edits

    Identify financial/authorization/business rules to validate later.

Pass Criteria:
No logic misuse possible under normal flows.

Fail Criteria:
Business logic abuse vectors (e.g., price override) identified.

Screenshots:

    Workflow screenshots for logic validation

    Parameter tampering examples

🔹 10. Identify WSDL files and hidden web service endpoints

Objective:
Discover SOAP or legacy web services via .wsdl files or parameter fuzzing.

Steps:

    Try:

        /service.wsdl, /webservice?wsdl, /api/soap?wsdl

    Use Burp or wfuzz to fuzz ?wsdl, ?wsdl2, etc.

    If found, import in SOAP UI and analyze services/functions.

Pass Criteria:
No exposed WSDL or secured properly with auth.

Fail Criteria:
Exposed WSDL file revealing internal service methods or logic.

Screenshots:

    WSDL content showing methods

    SOAP UI interface with accessible operations

✅ Phase 4 – Manual Testing: Configuration Management
🔹 1. Verify SSL Certificate Validity

Objective:
Ensure SSL/TLS certificates are valid, correctly configured, and not expired.

Steps:

    Visit the target domain in a browser and inspect the certificate.

    Use:

    openssl s_client -connect target.com:443

    or tools like testssl.sh or sslscan.

    Check:

        Validity period

        Issuer

        Common Name (CN)/Subject Alternative Name (SAN)

        Key length (≥ 2048 bits)

        Signature algorithm (avoid SHA-1)

Pass Criteria:
Certificate is valid, trusted, current, and uses secure settings.

Fail Criteria:
Expired, self-signed, mismatched domain, or weak algorithm used.

Screenshots:

    Browser SSL cert view

    testssl.sh/openssl output showing expiry, key length

🔹 2. Test for Cross-Frame Scripting (Clickjacking)

Objective:
Ensure that framing is blocked via security headers.

Steps:

    Use Burp or a browser dev tool to check response headers:

        Look for: X-Frame-Options or CSP with frame-ancestors

    Use tools like Clickjacking PoC Generator or create a basic iframe:

    <iframe src="https://target.com" width="800" height="600"></iframe>

Pass Criteria:
X-Frame-Options: DENY or SAMEORIGIN, or CSP present and blocks embedding.

Fail Criteria:
Page can be embedded in iframes, headers missing or misconfigured.

Screenshots:

    Response headers

    Working PoC showing the site embedded

🔹 3. Test for HTTP Methods (OPTIONS, PUT, DELETE, etc.)

Objective:
Ensure dangerous HTTP methods are disabled.

Steps:

    Run:

curl -X OPTIONS -i https://target.com

Alternatively use nmap:

    nmap -p 443 --script http-methods target.com

    Check allowed methods in response headers.

Pass Criteria:
Only GET, POST, HEAD, OPTIONS are allowed (OPTIONS only for preflight CORS).

Fail Criteria:
PUT, DELETE, TRACE, or CONNECT are allowed.

Screenshots:

    Curl or nmap output showing allowed methods

🔹 4. Enumerate Infra/Admin Interfaces

Objective:
Discover backend or admin interfaces exposed to unauthorized users.

Steps:

    Fuzz URLs:

        /admin, /administrator, /manage, /cpanel, /phpmyadmin

    Use dirb, gobuster, or ffuf with wordlists like common.txt, raft:

    ffuf -u https://target.com/FUZZ -w wordlist.txt

    Analyze responses for exposed admin panels.

Pass Criteria:
Admin panels protected with authentication or not publicly accessible.

Fail Criteria:
Unprotected admin panels or interfaces found.

Screenshots:

    Tool output showing discovered paths

    Access to admin panel without auth

🔹 5. Verify HTTPS Usage for Sensitive Data

Objective:
Ensure all sensitive operations use secure HTTPS transport.

Steps:

    Perform login/reset or sensitive transactions.

    Check whether the full request/response uses HTTPS.

    Analyze browser dev tools and proxy history.

Pass Criteria:
All forms and credentials submitted over HTTPS.

Fail Criteria:
Login or sensitive data sent over HTTP.

Screenshots:

    Network request showing HTTP used

    Login form action over HTTP

🔹 6. Verify HTTP Security Headers

Objective:
Check for presence and correct configuration of security headers.

Steps:

    Use Burp or curl:

    curl -I https://target.com

    Check for:

        Strict-Transport-Security

        X-Frame-Options

        X-XSS-Protection

        X-Content-Type-Options

        Content-Security-Policy

        Referrer-Policy

Pass Criteria:
All key headers are present and properly configured.

Fail Criteria:
Headers missing, misconfigured, or using insecure values.

Screenshots:

    Header output from curl/Burp

    Absence of key headers

🔹 7. Attempt Direct Access to Non-Web Files

Objective:
Check if sensitive file types (e.g., PDFs, DOCs, XLSs) can be accessed unauthenticated.

Steps:

    Try accessing:

        /files/, /uploads/, /docs/

    Look in robots.txt or sitemap.xml for file paths.

    Use ffuf or dirb to fuzz with .pdf, .xls, .doc, .sql extensions.

Pass Criteria:
Access denied or authentication required.

Fail Criteria:
Direct access to internal documents or database dumps.

Screenshots:

    Successful unauthenticated access to internal files

    Sensitive file downloaded without login

🔹 8. Test for S3 Bucket Misconfiguration (If Hosted in Cloud)

Objective:
Identify publicly exposed S3 buckets or improperly set ACLs.

Steps:

    Check for URLs pointing to S3:

        https://bucketname.s3.amazonaws.com

    Use awscli:

    aws s3 ls s3://bucket-name --no-sign-request

    Use tools like s3scanner, s3recon, or bucket_finder.

Pass Criteria:
Buckets not listable or require authentication.

Fail Criteria:
Unprotected buckets or files accessible anonymously.

Screenshots:

    File listing from public S3 bucket

    Sensitive file accessed from misconfigured S3

✅ Phase 5 – Manual Testing: Authentication Testing
🔹 1. Test for User Enumeration Vulnerabilities

Objective:
Ensure the application does not reveal whether a username/email exists.

Steps:

    Attempt login with:

        A valid username and invalid password.

        An invalid username and any password.

    Compare responses (status codes, messages, timing).

Pass Criteria:
Error messages are generic (e.g., “Invalid credentials”), same status and response time.

Fail Criteria:
Different responses for valid vs. invalid users (e.g., “User not found”).

Screenshots:

    Login responses for valid vs. invalid usernames

🔹 2. Test for Account Lockout Settings

Objective:
Verify whether there’s a mechanism to limit repeated failed login attempts.

Steps:

    Attempt multiple failed logins with same credentials.

    Observe if account gets locked or rate-limited.

Pass Criteria:
Account lockout or CAPTCHA/multi-factor enabled after threshold.

Fail Criteria:
Unlimited failed attempts allowed without control.

Screenshots:

    Login attempt logs

    Lockout message or absence thereof

🔹 3. Analyse Whether Account Lockout Could Cause DoS

Objective:
Identify whether brute-force lockout could be abused to lock others' accounts.

Steps:

    Trigger lockout using a known valid username.

    Log in successfully as user (if possible).

    Attempt multiple failed logins as victim.

Pass Criteria:
Lockout logic uses per-IP rate limiting or CAPTCHA.

Fail Criteria:
Any user can lock out another user.

Screenshots:

    Demonstration of remote account lockout

🔹 4. Attempt to Bypass Account Lockout

Objective:
Determine if account lockout mechanisms can be bypassed via header/IP tricks.

Steps:

    Use Burp Intruder with X-Forwarded-For header rotation.

    Attempt login attempts beyond the limit using spoofed IPs.

Pass Criteria:
Lockout triggers based on username or centralized logic.

Fail Criteria:
Bypassable via IP header manipulation.

Screenshots:

    Logs or traffic showing bypassed lockout

🔹 5. Test Forced Browsing to Bypass Authentication

Objective:
Check whether unauthorized access is possible by directly navigating to protected URLs.

Steps:

    Log out or use incognito browser.

    Try accessing authenticated URLs directly (e.g., /dashboard, /admin).

Pass Criteria:
Redirect to login or 403/401 error.

Fail Criteria:
Access allowed without authentication.

Screenshots:

    Successful unauthenticated access

🔹 6. Test Parameter or Response Tampering to Bypass Authentication

Objective:
Verify if parameters like auth=0 or status codes can be manipulated to skip auth.

Steps:

    Use Burp Repeater to replay login with tampered response headers.

    Modify parameters in requests (e.g., auth, is_admin, etc.)

Pass Criteria:
Server correctly validates session on backend.

Fail Criteria:
Client-side or insecure validation logic allows bypass.

Screenshots:

    Tampered request and successful unauthorized access

🔹 7. SQLi on Login Page to Bypass Authentication

Objective:
Test for classic SQL injection in login parameters.

Steps:

    Use payloads:

        ' OR 1=1--

        admin'--

        ' OR '1'='1'--

    Monitor for successful login without credentials.

Pass Criteria:
No SQLi allowed, input sanitized.

Fail Criteria:
Login bypass using SQLi.

Screenshots:

    SQLi payload in login

    Access granted as admin or any user

🔹 8. Check if Password Autocomplete is Disabled

Objective:
Prevent stored passwords from being auto-filled.

Steps:

    Open login page in browser.

    Inspect HTML of input fields.

    Check for autocomplete="off" on password inputs.

Pass Criteria:
Autocomplete disabled on sensitive forms.

Fail Criteria:
Browser auto-fills passwords.

Screenshots:

    HTML source showing presence or absence of autocomplete="off"

🔹 9. Test Password Reset / Reminder Bypass

Objective:
Check if password reset flow can be guessed or manipulated.

Steps:

    Initiate password reset for a user.

    Try guessing or manipulating:

        Token in reset link

        Email parameters

        Host headers

Pass Criteria:
Reset link is unguessable, bound to user/IP, and expires.

Fail Criteria:
Reset token is predictable or tampered.

Screenshots:

    Reset token pattern or manipulation leading to access

🔹 10. Session Termination and Reaccess After Logout

Objective:
Ensure session is fully invalidated after logout.

Steps:

    Log in and capture session cookie.

    Log out and replay authenticated request with saved cookie.

Pass Criteria:
Session token is invalidated; reaccess fails.

Fail Criteria:
Old token remains valid.

Screenshots:

    Burp requests using invalidated token

🔹 11. Check for Password Strength Enforcement

Objective:
Enforce strong password policies.

Steps:

    Try setting passwords like 123456, password, test@123.

    Observe error messages and validation.

Pass Criteria:
Weak passwords are rejected.

Fail Criteria:
Common or dictionary passwords allowed.

Screenshots:

    Weak password set successfully or rejected with proper message

🔹 12. Check for Old Password Requirement in Password Change

Objective:
Ensure users must enter the current password before changing it.

Steps:

    Attempt password change without entering the old password.

    Try using only session or cookie auth.

Pass Criteria:
Old password is required to change password.

Fail Criteria:
Users can change password without re-authentication.

Screenshots:

    Password change form behavior

🔹 13. Host Header Poisoning in Password Reset

Objective:
Manipulate password reset URL to redirect to attacker-controlled domain.

Steps:

    Initiate password reset.

    Modify Host header to attacker domain.

    Receive reset link and check domain.

Pass Criteria:
Application validates Host header and uses canonical domain.

Fail Criteria:
Link contains attacker’s domain.

Screenshots:

    Email/response showing reset link with poisoned host

🔹 14. Re-authentication for Critical Actions

Objective:
Verify if the app prompts re-authentication before performing sensitive actions.

Steps:

    Perform critical actions (e.g., delete account, change password/email).

    Check if re-authentication is enforced.

Pass Criteria:
Session validation or password prompt required.

Fail Criteria:
Sensitive actions performable without password.

Screenshots:

    Critical action performed without prompt

🔹 15. Bypass Security Questions

Objective:
Check whether weak or guessable answers to security questions allow unauthorized access.

Steps:

    Attempt reset using common answers (mother’s maiden name, blue, etc.).

    Brute-force questions with known info.

Pass Criteria:
Security questions are not used or strongly implemented.

Fail Criteria:
Guessable answers lead to account takeover.

Screenshots:

    Security questions and successful reset using known answers

🔹 16. Unique User IDs

Objective:
Ensure usernames/user IDs are unique per user.

Steps:

    Register with the same username/email multiple times.

    Analyze API responses for duplication check.

Pass Criteria:
App prevents duplicates and enforces uniqueness.

Fail Criteria:
Duplicate user IDs allowed.

Screenshots:

    Registration bypass or API response

🔹 17. Use of Basic HTTP Authentication

Objective:
Identify whether weak HTTP Basic Auth is being used.

Steps:

    Intercept requests.

    Check for:

        Authorization: Basic <base64>

        Use of .htaccess protected folders

Pass Criteria:
No Basic Auth used or it’s over HTTPS with limited scope.

Fail Criteria:
Credentials sent in plain text or over HTTP.

Screenshots:

    Header showing Basic Auth credentials


✅ Phase 6 – Manual Testing: Authorization
🔹 1. Direct Browse to High Privileged Pages Unauthenticated or Low Privileged

Objective:
Verify that restricted pages cannot be accessed without proper authorization.

Steps:

    Log out or use an unauthenticated session.

    Attempt to access URLs/pages that require high privilege (e.g., /admin, /user/settings, /payments).

    Log in as a low privileged user and try to access high privileged pages.

    Observe response codes and page content.

Pass Criteria:
Access denied with 401/403 or redirect to login page.

Fail Criteria:
Page content accessible or no access control enforced.

Screenshots:

    Direct access attempt as unauthenticated user

    Direct access attempt as low privileged user

🔹 2. Attempt Full Path Disclosure Attacks (e.g., page[]=...)

Objective:
Check if the application leaks filesystem paths via parameters.

Steps:

    Identify parameters that accept array or file path inputs, such as page[]=.

    Inject payloads such as:

        ../../../../etc/passwd

        C:\Windows\System32\drivers\etc\hosts

    Observe responses for path disclosures or errors revealing file system info.

Pass Criteria:
No path disclosure or generic error messages.

Fail Criteria:
Detailed filesystem paths or errors leaked.

Screenshots:

    Response showing full path disclosure

🔹 3. Test Cookie Manipulation for Access Control Bypass

Objective:
Verify whether tampering with cookies allows privilege escalation.

Steps:

    Identify cookies related to authorization or role (e.g., role=, isAdmin=, user_level=).

    Use Burp Suite or browser dev tools to modify cookie values to higher privilege levels.

    Refresh page or resend request with manipulated cookies.

    Verify if access changes accordingly.

Pass Criteria:
Cookie modifications are rejected or invalidated.

Fail Criteria:
Privilege escalation or unauthorized access through cookie tampering.

Screenshots:

    Before and after cookie values and page access

🔹 4. Test Parameter Manipulation (IDOR)

Objective:
Detect Insecure Direct Object References allowing unauthorized data access.

Steps:

    Identify parameters that reference objects or users, e.g., user_id=1234.

    Modify parameters to other user or object IDs.

    Attempt to access or modify data belonging to others.

    Verify if access control is enforced.

Pass Criteria:
Access denied when accessing others' resources.

Fail Criteria:
Unauthorized data accessed or modified.

Screenshots:

    Requests with manipulated parameters

    Responses showing unauthorized data

🔹 5. HTTP Request Headers Tested for Directory Traversal

Objective:
Check if HTTP headers can be used to perform directory traversal attacks.

Steps:

    Identify headers like X-Forwarded-For, Referer, User-Agent.

    Inject payloads like ../../../../etc/passwd or %2e%2e%2f in headers.

    Observe server responses for leakage or file content.

Pass Criteria:
No leakage or errors revealing file system.

Fail Criteria:
Directory traversal succeeds or path info disclosed via headers.

Screenshots:

    Request headers with payload

    Server response evidencing traversal

✅ Phase 7 – Manual Testing: Session Management Testing
🔹 1. Verify Session Timeout Enforced in a Reasonable Amount of Time

Objective:
Ensure sessions expire after a set period of inactivity.

Steps:

    Log in to the application.

    Leave the session idle without any activity for the expected timeout duration (e.g., 15, 30 minutes).

    Attempt to perform an authenticated action or refresh a page after timeout.

Pass Criteria:
User is logged out or required to re-authenticate.

Fail Criteria:
Session remains active with no re-authentication.

Screenshots:

    Initial logged-in state

    Post-timeout access attempt and response

🔹 2. Check for Session Fixation Vulnerabilities

Objective:
Verify that session IDs are regenerated upon authentication.

Steps:

    Obtain a valid session ID as an unauthenticated user.

    Log in using this session ID without it being regenerated.

    Check if the session ID changes after login.

Pass Criteria:
Session ID changes immediately after login.

Fail Criteria:
Session ID remains the same, enabling fixation attacks.

Screenshots:

    Session ID before login

    Session ID after login

🔹 3. Verify Session ID is Never Sent Over Unencrypted Connections (HTTP)

Objective:
Ensure session tokens are only transmitted over HTTPS.

Steps:

    Monitor network traffic during authenticated sessions using tools like Burp or Wireshark.

    Attempt to access the site over HTTP and observe if the session ID is sent.

Pass Criteria:
Session tokens are never sent over HTTP.

Fail Criteria:
Session tokens visible in unencrypted HTTP requests.

Screenshots:

    Network capture showing session ID only on HTTPS requests

    Any HTTP request showing session tokens (fail)

🔹 4. Check if Session ID is Sent in GET Requests

Objective:
Prevent session tokens exposure in URLs.

Steps:

    Monitor all requests for session tokens in URL parameters.

    Attempt to force the application to place session IDs in the URL (e.g., URL rewriting).

Pass Criteria:
Session tokens never appear in URLs.

Fail Criteria:
Session tokens visible in URL parameters or query strings.

Screenshots:

    Example request URL without session tokens

    Any URL containing session token (fail)

🔹 5. Test Entropy and Predictability of Session IDs

Objective:
Verify session tokens are cryptographically strong and unpredictable.

Steps:

    Capture multiple session tokens.

    Analyze tokens for patterns, length, character set.

    Attempt to predict or brute force session tokens (using tools like Burp Suite’s session token analyzer or custom scripts).

Pass Criteria:
Session tokens are random, unique, and not guessable.

Fail Criteria:
Predictable, sequential, or guessable tokens.

Screenshots:

    Sample tokens captured

    Analysis showing randomness/predictability

🔹 6. Check if Session IDs are Encoded and Predictable (e.g., base64, Unix timestamp)

Objective:
Detect weak session token encoding that leaks info or enables attacks.

Steps:

    Inspect session tokens for encoding (Base64, JWT, timestamps).

    Decode tokens where applicable and check for predictable data like timestamps, user IDs.

    Attempt to use decoded tokens to impersonate other users.

Pass Criteria:
Tokens do not reveal sensitive info or are not predictable.

Fail Criteria:
Tokens reveal internal info or enable impersonation.

Screenshots:

    Token before and after decoding

    Proof of concept for impersonation (if possible)

🔹 7. Verify New Session ID Issued on Authentication and Secure Section Entry

Objective:
Ensure session IDs are refreshed upon login and privilege escalation.

Steps:

    Capture session ID before login.

    Log in and capture new session ID.

    Navigate to secure areas that require higher privilege; observe session ID changes.

Pass Criteria:
Session ID changes on login and privilege changes.

Fail Criteria:
Session ID remains unchanged.

Screenshots:

    Session ID before login

    Session ID after login

    Session ID before and after accessing secure areas

🔹 8. Test if Concurrent Logins are Possible

Objective:
Check if the application allows multiple simultaneous sessions per user.

Steps:

    Log in with the same user credentials in two different browsers or devices.

    Perform actions on both sessions.

    Observe if any session invalidation or alerts occur.

Pass Criteria:
Concurrent sessions allowed or appropriately restricted per policy.

Fail Criteria:
Sessions conflict causing security issues, or policy violations.

Screenshots:

    Both sessions active simultaneously

    Any error messages or warnings

🔹 9. Verify Logout Button Presence on All Authenticated Pages

Objective:
Ensure users have an explicit way to terminate sessions.

Steps:

    Navigate through all authenticated pages.

    Verify presence of logout or sign-out controls.

Pass Criteria:
Logout button present on all authenticated pages.

Fail Criteria:
Logout missing or hidden.

Screenshots:

    Authenticated page with visible logout button

🔹 10. Check Session Transfer Across Different Technologies or Languages

Objective:
Ensure session management consistency across multi-technology environments.

Steps:

    Identify if the app spans multiple frameworks (e.g., PHP frontend, Java backend).

    Authenticate and move between different technology boundaries.

    Observe if sessions persist or break unexpectedly.

Pass Criteria:
Sessions remain consistent and secure.

Fail Criteria:
Sessions lost, or insecure session transfer.

Screenshots:

    Session token values before and after crossing technology boundaries

🔹 11. Identify Cookies Used for Session Management

Objective:
Catalog cookies responsible for session handling.

Steps:

    Capture cookies after authentication.

    Analyze cookies for usage related to sessions.

Pass Criteria:
Cookies properly named and scoped.

Fail Criteria:
Session cookies unclear or mixed with non-session cookies.

Screenshots:

    Cookie list with session cookies highlighted

🔹 12. Check Cookies for Persistent Expiry

Objective:
Verify whether session cookies are persistent or session-only.

Steps:

    Inspect cookie attributes for Expires or Max-Age.

    Confirm that session cookies expire on browser close unless intended otherwise.

Pass Criteria:
Session cookies expire appropriately.

Fail Criteria:
Session cookies persist longer than intended.

Screenshots:

    Cookie attributes showing expiry settings

🔹 13. Check Set-Cookie Header for Secure Flag

Objective:
Ensure cookies are only transmitted over HTTPS.

Steps:

    Inspect Set-Cookie headers for the Secure flag.

    Verify application forces HTTPS for sensitive cookies.

Pass Criteria:
Secure flag set on cookies used for sessions.

Fail Criteria:
Cookies without Secure flag sent over HTTPS.

Screenshots:

    HTTP response headers showing Set-Cookie with Secure flag

🔹 14. Check Set-Cookie Header for HttpOnly Flag

Objective:
Prevent JavaScript access to session cookies.

Steps:

    Inspect Set-Cookie headers for the HttpOnly flag.

Pass Criteria:
HttpOnly flag set on session cookies.

Fail Criteria:
Cookies accessible to JavaScript.

Screenshots:

    Set-Cookie headers showing HttpOnly

🔹 15. Check If Cookies Are Set With Defined Scope (Not /)

Objective:
Ensure cookies are scoped to appropriate paths to reduce exposure.

Steps:

    Inspect cookie Path attribute.

    Verify cookies are not set globally (Path=/) if unnecessary.

Pass Criteria:
Cookies scoped to minimum required path.

Fail Criteria:
Cookies unnecessarily scoped globally.

Screenshots:

    Cookie Path attribute values

🔹 16. Analyze Content of All Application Cookies

Objective:
Check for sensitive or unnecessary information in cookies.

Steps:

    Review cookie values and flags.

    Identify any sensitive data (e.g., passwords, tokens in plaintext).

Pass Criteria:
No sensitive info stored in cookies.

Fail Criteria:
Sensitive info stored insecurely in cookies.

Screenshots:

    Cookie contents (redacted as needed)

🔹 17. Check Cache-Control Header is Private or Better

Objective:
Prevent caching of sensitive pages.

Steps:

    Inspect HTTP response headers for Cache-Control.

    Confirm private, no-store or no-cache settings on authenticated content.

Pass Criteria:
Proper cache control preventing caching by proxies or shared caches.

Fail Criteria:
Sensitive pages cached publicly.

Screenshots:

    Response headers showing Cache-Control

🔹 18. Check Pragma Header is Set to No-Cache

Objective:
Support backward compatibility for cache control.

Steps:

    Inspect HTTP response headers for Pragma: no-cache.

Pass Criteria:
Pragma: no-cache set for authenticated pages.

Fail Criteria:
Pragma header missing or incorrectly set.

Screenshots:

    Response headers showing Pragma: no-cache

🔹 19. Check Expires Header is Pre-expired

Objective:
Ensure content is not cached past expiration.

Steps:

    Inspect HTTP response headers for Expires value.

    Confirm it is set to a past date/time.

Pass Criteria:
Expires header set to past date/time.

Fail Criteria:
Expires header set to future date/time allowing caching.

Screenshots:

    Response headers showing Expires date

🔹 20. Test for CSRF Protection Enabled for State-Changing Requests

Objective:
Confirm application defends against Cross-Site Request Forgery.

Steps:

    Identify state-changing requests (POST/PUT/DELETE).

    Check for CSRF tokens in requests (hidden fields, headers).

    Attempt sending requests without CSRF tokens or with reused tokens.

Pass Criteria:
Requests without valid tokens are rejected.

Fail Criteria:
State-changing requests accepted without valid CSRF tokens.

Screenshots:

    Request with valid CSRF token

    Request without/invalid token and response

🔹 21. Test for CSRF Bypass Techniques

Objective:
Attempt common CSRF bypasses (token removal, GET request conversion, token reuse).

Steps:

    Remove CSRF token and send request.

    Convert POST to GET removing CSRF token and resend.

    Resend request with reused token multiple times.

Pass Criteria:
All bypass attempts fail.

Fail Criteria:
Bypass succeeds, state change occurs without token validation.

Screenshots:

    Bypass attempts and server responses

✅ Phase 8 – Manual Testing: Input Validation Testing
🔹 1. Cross Site Scripting (XSS) Manual Testing

Objective:
Detect reflected, stored, and DOM-based XSS vulnerabilities.

Steps:

    Identify all input vectors (GET/POST parameters, headers, cookies, JSON bodies).

    Inject XSS payloads such as:

        <script>alert(1)</script>

        "><svg/onload=alert(1)>

        "><img src=x onerror=alert(1)>

    Observe if payload is reflected or stored and executed in the browser.

    Test DOM-based vectors by injecting payloads in client-side script contexts (e.g., fragment, localStorage).

Pass Criteria:
Payloads do not execute and are properly escaped or sanitized.

Fail Criteria:
Payload executes or causes JS alert/pop-up.

Screenshots:

    Input form with injected payload

    Resulting page with alert/pop-up or reflected payload

🔹 2. Cookies Tested for XSS

Objective:
Check if cookies are vulnerable to client-side injection attacks.

Steps:

    Insert XSS payloads into cookie values.

    Reload application pages and monitor for execution of scripts.

Pass Criteria:
Cookie values are sanitized and do not execute scripts.

Fail Criteria:
XSS triggered via cookie payload.

Screenshots:

    Modified cookie with payload

    Evidence of XSS execution

🔹 3. HTTP Headers Tested for XSS

Objective:
Verify header injection or reflected XSS via HTTP headers.

Steps:

    Inject XSS payloads into headers such as User-Agent, Referer, or custom headers.

    Observe if payload is reflected in response or page source and executed.

Pass Criteria:
Headers are sanitized and no XSS occurs.

Fail Criteria:
Payload execution through headers.

Screenshots:

    Request headers with payload

    Page source or alert popup

🔹 4. SQL Injection Manual Testing

Objective:
Detect SQL Injection vulnerabilities via input fields or parameters.

Steps:

    Identify inputs used in SQL queries.

    Inject common SQL payloads such as ' OR '1'='1, ' OR 1=1--, ' UNION SELECT NULL-- etc.

    Observe application behavior, error messages, or data leakage.

Pass Criteria:
Inputs are properly parameterized or sanitized; no abnormal behavior.

Fail Criteria:
SQL errors, data leakage, or unauthorized access.

Screenshots:

    Input field with payload

    Application response with error or leaked data

🔹 5. Blind SQL Injection Testing

Objective:
Identify SQL Injection where error messages are not shown.

Steps:

    Use time-based payloads like:

        ' WAITFOR DELAY '0:0:5'-- (MSSQL)

        ' OR IF(1=1,SLEEP(5),0)-- (MySQL)

    Measure response times for injected payloads vs. normal requests.

Pass Criteria:
No timing delays or abnormal behavior.

Fail Criteria:
Response delay indicates injection point.

Screenshots:

    Request with timing payload

    Timing difference logged or displayed

🔹 6. Cookies Tested for SQL Injection

Objective:
Check if SQL injection possible via cookies.

Steps:

    Insert SQL payloads into cookie values.

    Send requests and observe backend behavior or errors.

Pass Criteria:
Cookies sanitized; no SQLi possible.

Fail Criteria:
SQL errors or data leakage via cookies.

Screenshots:

    Modified cookie with payload

    Server response showing errors or anomalies

🔹 7. LDAP Injection Manual Testing

Objective:
Detect LDAP Injection vulnerabilities.

Steps:

    Inject LDAP special characters like *, |, &, (, ) in inputs.

    Try to modify LDAP queries, e.g., *)(|(userPassword=*)).

    Observe if injected input changes LDAP results or causes errors.

Pass Criteria:
LDAP queries sanitized or parameterized; no injection.

Fail Criteria:
LDAP query manipulated or errors thrown.

Screenshots:

    Input with LDAP payload

    Application response/errors

🔹 8. XML & XPath Injection Testing

Objective:
Test XML and XPath inputs for injection flaws.

Steps:

    Identify XML/XPath input points.

    Inject payloads such as '] | //user[password/text()=''] | //user['.

    Observe data leakage, errors, or unauthorized access.

Pass Criteria:
Inputs sanitized; no injection possible.

Fail Criteria:
Sensitive data exposed or errors observed.

Screenshots:

    Injected XML/XPath payload

    Application response or error

🔹 9. Blind XPath Injection Testing

Objective:
Detect blind XPath injection where error messages are suppressed.

Steps:

    Use boolean or time-based payloads in XPath queries.

    Monitor response behavior changes based on payloads.

Pass Criteria:
No differences in application response.

Fail Criteria:
Response changes indicating injection.

Screenshots:

    Request payloads with boolean/time tests

    Response time or content differences

🔹 10. Path Traversal Testing

Objective:
Detect directory traversal vulnerabilities.

Steps:

    Test inputs with traversal payloads like ../, ..%2f, %2e%2e/.

    Attempt to access sensitive files like /etc/passwd, windows\win.ini.

Pass Criteria:
Traversal attempts blocked or sanitized.

Fail Criteria:
Sensitive files disclosed or accessible.

Screenshots:

    Input with traversal payload

    Response showing file contents

🔹 11. Cookies Tested for Path Traversal

Objective:
Check path traversal via cookies.

Steps:

    Insert traversal payloads into cookie values.

    Observe server behavior or errors.

Pass Criteria:
No traversal possible through cookies.

Fail Criteria:
Path traversal vulnerability triggered.

Screenshots:

    Cookie with payload

    Server response/errors

🔹 12. Command Injection Testing

Objective:
Identify if application allows injection of OS commands.

Steps:

    Inject OS command payloads like ; ls, | whoami, && id.

    Observe command execution results or errors.

Pass Criteria:
Commands not executed; input sanitized.

Fail Criteria:
Command output or execution visible.

Screenshots:

    Payload in input field

    Output or error message showing command execution

🔹 13. Server-side JavaScript Injection Testing (Node.js Apps)

Objective:
Detect injection vulnerabilities in server-side JS environments.

Steps:

    Identify inputs processed by Node.js.

    Inject payloads to manipulate JS logic or eval calls.

    Observe execution or errors.

Pass Criteria:
No injection possible; input safely handled.

Fail Criteria:
Code injection or execution.

Screenshots:

    Injected payload

    Server response or error

🔹 14. HTTP Response Splitting/Smuggling

Objective:
Check if input allows splitting/smuggling of HTTP responses.

Steps:

    Inject CRLF sequences (%0d%0a) in headers or parameters.

    Observe if additional headers or responses injected.

Pass Criteria:
Input sanitized; no response splitting.

Fail Criteria:
Injected headers or split responses observed.

Screenshots:

    Request with CRLF payload

    Response showing injection

🔹 15. XML External Entity (XXE) Injection Testing

Objective:
Detect XXE vulnerabilities in XML parsers.

Steps:

    Inject XML payloads referencing external entities.

    Use Burp Collaborator for OOB detection.

    Check for sensitive data leakage or SSRF.

Pass Criteria:
XXE payloads blocked or sanitized.

Fail Criteria:
External entities resolved; data leakage or SSRF.

Screenshots:

    Payload XML sent

    Evidence of entity resolution or OOB interaction

🔹 16. XXE via File Upload

Objective:
Test if XML files uploaded trigger XXE.

Steps:

    Upload crafted XML files with external entity references.

    Observe server processing or network interactions.

Pass Criteria:
Uploads sanitized; no XXE triggered.

Fail Criteria:
XXE executed after upload.

Screenshots:

    Upload request with crafted file

    Server or network evidence

🔹 17. XXE via JSON to XML Conversion

Objective:
Test if JSON inputs are converted to XML causing XXE.

Steps:

    Identify JSON inputs converted server-side to XML.

    Inject JSON payloads triggering XXE.

Pass Criteria:
No XXE via JSON inputs.

Fail Criteria:
XXE triggered.

Screenshots:

    JSON payload

    Evidence of XXE triggered

🔹 18. Template Injection (Client and Server Side)

Objective:
Identify injection flaws in template engines.

Steps:

    Inject template payloads ({{7*7}}, ${7*7}) in input fields.

    Observe if templates execute on client or server.

Pass Criteria:
Payloads rendered as text, no execution.

Fail Criteria:
Template executes and leaks data or executes code.

Screenshots:

    Input with template payload

    Rendered output showing execution

🔹 19. Buffer Overflow Testing

Objective:
Test for buffer overflow vulnerabilities.

Steps:

    Send large input payloads exceeding expected buffer sizes.

    Monitor application behavior (crashes, errors).

Pass Criteria:
Input safely handled; no crashes.

Fail Criteria:
Application crashes or behaves abnormally.

Screenshots:

    Payload size details

    Application response or crash logs

🔹 20. Generic User Input Validation

Objective:
Test exotic encodings and input sanitization (SSI, Unicode, URL encoding).

Steps:

    Inject encoded payloads: %uXXXX, nested URL encoding, SSI tags (<!--#exec-->).

    Observe if input is decoded and executed.

Pass Criteria:
Input properly sanitized.

Fail Criteria:
Input executed or interpreted improperly.

Screenshots:

    Encoded payloads

    Application response

🔹 21. Insecure Deserialization Testing

Objective:
Detect unsafe deserialization that allows code execution or data manipulation.

Steps:

    Identify serialized inputs (JSON, XML, PHP serialization, Java serialization).

    Modify serialized data with malicious payloads.

    Observe server behavior or code execution.

Pass Criteria:
Deserialization safe and validated.

Fail Criteria:
Code execution or data corruption.

Screenshots:

    Modified serialized data

    Server response or error

🔹 22. CSV Injection / Formula Injection Testing

Objective:
Check if CSV export inputs allow formula injection.

Steps:

    Inject formulas starting with =, +, -, @ in inputs exported to CSV.

    Download CSV and open in spreadsheet apps to see if formula executes.

Pass Criteria:
Inputs sanitized or escaped.

Fail Criteria:
Formulas execute causing potential harm.

Screenshots:

    Input with formula payload

    CSV export showing formula execution

🔹 23. Server-Side Request Forgery (SSRF) Testing

Objective:
Test if application can be abused to make requests to internal or external systems.

Steps:

    Identify inputs that make server-side HTTP requests (URLs, fetches).

    Inject URLs pointing to internal resources or attacker-controlled servers.

    Use Burp Collaborator or listener to detect outbound requests.

Pass Criteria:
SSRF prevented or restricted.

Fail Criteria:
Outbound requests to attacker domains or internal hosts possible.

Screenshots:

    Payload with internal/external URL

    Collaborator evidence of outbound request

🔹 24. External Service Interaction (Burp Collaborator)

Objective:
Detect out-of-band vulnerabilities triggered via external service interactions.

Steps:

    Use Burp Collaborator payloads in inputs (XXE, SSRF, Injection).

    Monitor Collaborator for callbacks indicating vulnerability.

Pass Criteria:
No out-of-band callbacks.

Fail Criteria:
Collaborator logs show interaction.

Screenshots:

    Payloads sent

    Collaborator logs

🔹 25. NoSQL Injection Testing

Objective:
Detect injection in NoSQL database queries.

Steps:

    Identify inputs used in NoSQL queries (MongoDB, CouchDB).

    Inject NoSQL payloads like {"$ne": null}, {"$gt": ""}.

    Observe if injection bypasses filters or causes data leaks.

Pass Criteria:
Inputs sanitized; no injection.

Fail Criteria:
Injection allows bypass or data access.

Screenshots:

    Payloads in input

    Server response or data leakage

🔹 26. Unmasked Sensitive Data Testing

Objective:
Check if sensitive data like passwords or tokens are exposed.

Steps:

    Inspect responses for sensitive data in HTML, headers, or JSON.

    Test if data is masked or obfuscated properly.

Pass Criteria:
Sensitive data not exposed.

Fail Criteria:
Sensitive data visible in responses.

Screenshots:

    Response snippets showing data exposure

✅ Phase 9 – Manual Testing: Error Handling
🔹 1. Determine if Application Uses Custom Errors or Error Suppression

Objective:
Identify if the application uses generic/custom error pages or suppresses error details.

Steps:

    Trigger common errors (e.g., enter invalid URL paths, submit invalid input types, malformed requests).

    Observe error messages shown (detailed stack traces, generic messages, or no message).

    Test for differences in error messages between authenticated and unauthenticated users.

Pass Criteria:
Application shows generic/custom error messages without sensitive data.

Fail Criteria:
Detailed stack traces or system info exposed.

Screenshots:

    Screenshot of generic error page

    Screenshot of detailed error stack trace (if any)

🔹 2. Provoke Errors and Analyze for Information Leakage

Objective:
Test if errors leak sensitive system or application information.

Steps:

    Submit malformed inputs (e.g., SQL syntax errors ' OR '1'='1, special chars, malformed XML/JSON).

    Request non-existent resources or invalid HTTP methods.

    Observe error messages in responses or logs if accessible.

Pass Criteria:
Errors are generic, no sensitive data leakage.

Fail Criteria:
Error messages reveal database info, file paths, software versions, or internal IPs.

Screenshots:

    Input/request triggering error

    Detailed error message showing leaked info

🔹 3. Check HTML Source for Error Info

Objective:
Identify if error details are present in the HTML source code.

Steps:

    When error pages are displayed, view the page source.

    Look for hidden comments, stack traces, debug info, or error messages in the HTML.

Pass Criteria:
No sensitive or debug info in source.

Fail Criteria:
Sensitive error/debug info present in page source.

Screenshots:

    HTML source view with highlighted sensitive info

🔹 4. Check if Errors Reveal Application/Backend Structure

Objective:
Detect error messages that disclose internal architecture or technology stack.

Steps:

    Trigger errors (e.g., SQL injection with malformed payloads, invalid parameters).

    Analyze error messages for references to backend languages, databases, frameworks, or file paths.

Pass Criteria:
No internal structure disclosed.

Fail Criteria:
Errors expose technology details, file paths, database types, or framework versions.

Screenshots:

    Error messages showing internal details

✅ Phase 10 – Manual Testing: Testing For Weak Cryptography
🔹 1. Test SSL/TLS Version and Supported Cipher Strengths

Objective:
Identify use of weak SSL/TLS protocols and cipher suites that can compromise secure communications.

Steps:

    Use tools like testssl.sh, sslscan, or nmap --script ssl-enum-ciphers against the target host or web application IP/domain.

    Identify supported SSL/TLS versions (e.g., SSLv2, SSLv3, TLS 1.0, 1.1 are deprecated).

    Check for weak cipher suites such as RC4, DES, 3DES, NULL ciphers, export-grade ciphers, or those with weak key lengths (<128 bits).

    Verify support for modern protocols like TLS 1.2 or TLS 1.3 and strong cipher suites.

Pass Criteria:
Only secure protocols (TLS 1.2/1.3) and strong cipher suites (AES-GCM, CHACHA20, etc.) are supported. No deprecated protocols or weak ciphers.

Fail Criteria:
Support for deprecated SSL versions, weak ciphers, or export-grade ciphers found.

Screenshots:

    Output from testssl.sh or sslscan showing protocols and cipher suites

    Highlight sections indicating weak or deprecated protocols/ciphers

🔹 2. Check for Digital Certificate Validity (Duration, Signature, and CN)

Objective:
Ensure SSL certificates are valid, correctly signed, and configured with proper domain names.

Steps:

    Using a browser or openssl s_client, inspect the SSL certificate details.

    Check the certificate expiration date — it should be valid and not expired.

    Verify the certificate’s Common Name (CN) or Subject Alternative Name (SAN) matches the domain.

    Confirm that the certificate is issued by a trusted Certificate Authority (CA).

    Check for usage of weak signature algorithms (e.g., SHA1, MD5).

Pass Criteria:
Certificate is valid, not expired, matches domain, issued by trusted CA, and uses strong signature algorithm.

Fail Criteria:
Expired, self-signed, mismatched domain, or weak signature algorithm certificate.

Screenshots:

    Certificate details window highlighting validity period and CN/SAN

    Output from openssl s_client -connect <host>:443 -showcerts

🔹 3. Check Credentials Are Delivered Only Over HTTPS

Objective:
Verify that login forms, credentials, and sensitive data are transmitted exclusively over encrypted HTTPS connections.

Steps:

    Capture traffic via Burp Suite or a proxy while performing login or sensitive operations.

    Confirm the form submission URL uses HTTPS, not HTTP.

    Verify no credentials or session tokens are sent over unencrypted HTTP.

Pass Criteria:
All sensitive data transmitted strictly over HTTPS.

Fail Criteria:
Credentials or session tokens sent over HTTP.

Screenshots:

    Burp Suite HTTP history showing HTTPS login requests

    Any HTTP requests leaking credentials (if found)

🔹 4. Check If HTTP Strict Transport Security (HSTS) Is Enabled

Objective:
Confirm that the application enforces HTTPS by using the HSTS header to prevent downgrade attacks.

Steps:

    Inspect HTTP response headers using browser dev tools or Burp Suite.

    Look for the Strict-Transport-Security header with an appropriate max-age value.

    Confirm that subdomains are included if applicable (includeSubDomains).

Pass Criteria:
HSTS header present with reasonable max-age (e.g., > 6 months).

Fail Criteria:
No HSTS header or improperly configured header.

Screenshots:

    HTTP response headers with HSTS shown in Burp or browser tools

✅ Phase 11 – Manual Testing: Business Logic Testing
🔹 1. Attempt to Subvert Critical Business Logic

Objective:
Identify flaws where business rules or workflows can be bypassed, manipulated, or misused to gain unauthorized benefits or cause inconsistencies.

Steps:

    Understand the core business workflows (e.g., purchase flow, discount application, order processing).

    Attempt to manipulate parameters or workflow steps to bypass or change logic (e.g., skipping payment step but getting product access).

    Test edge cases such as submitting incomplete data, changing order quantities/prices, or bypassing validation on client and server side.

    Try using tools like Burp Suite to intercept and modify requests during workflow.

Pass Criteria:
All business logic enforcements are strictly validated server-side; unauthorized state changes are blocked.

Fail Criteria:
Business logic bypass or manipulation is successful resulting in unauthorized access or benefits.

Screenshots:

    Modified requests with altered business parameters

    Server responses showing unexpected acceptance or result

🔹 2. Business Logic Scenario: Tampering Price Before Payment

Objective:
Test if it’s possible to change the price or total amount during the order/payment process to pay less or receive more.

Steps:

    Intercept requests during checkout or payment with Burp Suite.

    Modify price or total amount fields before submission.

    Attempt replaying modified requests to complete transactions.

    Verify if the application recalculates or validates prices server-side.

Pass Criteria:
Price or total amount tampering is detected and rejected.

Fail Criteria:
Payment is processed with tampered price or amount.

Screenshots:

    Burp Suite request with modified price/amount fields

    Confirmation page showing manipulated price or payment success despite tampering

🔹 3. Business Logic Scenario: Obtain Offer Price Without Purchasing Criteria

Objective:
Check if promotional offers or discounts can be exploited without meeting purchase conditions (e.g., buying minimum quantity).

Steps:

    Identify offer eligibility criteria (e.g., minimum purchase quantity).

    Attempt to trigger discount or promo code application without fulfilling criteria.

    Modify requests or manipulate form fields to bypass checks.

    Validate server response for improper acceptance.

Pass Criteria:
Offer eligibility is strictly enforced server-side.

Fail Criteria:
Offers or discounts are applied despite unmet criteria.

Screenshots:

    Modified request showing bypass of purchase criteria

    Response applying discount or offer incorrectly

🔹 4. Business Logic Scenario: Brute Forcing Promo Codes

Objective:
Test the ability to enumerate valid promo or coupon codes by brute forcing or guessing.

Steps:

    Identify promo code input fields.

    Use automated tools or Burp Intruder to try sequential or dictionary-based codes.

    Observe responses for valid/invalid promo code feedback.

    Monitor rate limiting or lockout mechanisms.

Pass Criteria:
Rate limiting or captcha mechanisms prevent brute force; promo codes not enumerable.

Fail Criteria:
Valid promo codes discovered via brute forcing.

Screenshots:

    Burp Intruder attack showing promo code attempts

    Successful promo code validation responses

🔹 5. Manipulate Forms to Bypass Restrictions

Objective:
Test if client-side or server-side form validations can be bypassed to submit unauthorized or malformed data.

Steps:

    Identify forms with client-side validation (e.g., JS-based input checks).

    Disable JS or modify form data using Burp Suite or browser developer tools.

    Submit invalid or out-of-range data.

    Check if server accepts or rejects such data.

Pass Criteria:
Server-side validation correctly rejects invalid or unauthorized data.

Fail Criteria:
Server accepts data that bypasses client-side restrictions.

Screenshots:

    Modified form submission requests

    Server responses indicating acceptance of invalid data

🔹 6. Attempt Upload of Executable or EICAR Files

Objective:
Test upload filters by trying to upload potentially malicious files such as executables or EICAR test virus files.

Steps:

    Locate file upload functionalities.

    Attempt uploading executable files (.exe, .bat) or EICAR test file.

    Check if filters or antivirus scanning blocks uploads.

    Verify if uploaded files are accessible or executable.

Pass Criteria:
Uploads of forbidden files are blocked or sanitized; no executable files accepted.

Fail Criteria:
Malicious or executable files accepted/uploaded successfully.

Screenshots:

    Upload request with executable/EICAR file

    Server response or error message

    Access to uploaded file (if any)

🔹 7. Attempt to Bypass Upload Filters Using Null Byte, Content-Type Bypasses

Objective:
Test if upload restrictions can be bypassed by using null byte injection or manipulating Content-Type headers.

Steps:

    Attempt to append null byte (%00) to file names to bypass extension checks (e.g., file.php%00.jpg).

    Modify Content-Type headers during upload to misrepresent file type.

    Test double extensions or renamed files.

    Check if uploads succeed and files execute or are accessible.

Pass Criteria:
Upload filters detect and block bypass attempts.

Fail Criteria:
Upload filters bypassed; malicious files uploaded.

Screenshots:

    Modified upload request with bypass attempts

    Successful upload confirmation

✅ Phase 12 – Manual Testing: Client Side Testing
🔹 1. Test User Inputs from Client-Side JavaScript Objects (DOM XSS)

Objective:
Identify DOM-based Cross-Site Scripting vulnerabilities where user input is unsafely handled or reflected in client-side scripts.

Steps:

    Identify DOM sinks and sources by reviewing client-side JavaScript code or using Burp DOM Invader.

    Inject payloads (e.g., "><svg/onload=alert(1)>) into input points that affect DOM elements dynamically.

    Observe if payload executes in the browser context without server interaction.

    Use browser developer tools to trace script execution and DOM modifications.

Pass Criteria:
No DOM XSS payloads execute; all user inputs properly sanitized client-side and/or server-side.

Fail Criteria:
Payload executes in browser due to unsafe DOM manipulation.

Screenshots:

    Payload injection in browser input

    JavaScript console or alert popup showing XSS execution

🔹 2. Test HTML Injection

Objective:
Check for injection of arbitrary HTML code via user inputs that reflects on client side.

Steps:

    Insert HTML tags or scripts into input fields.

    Submit and observe rendered output on client side.

    Confirm whether HTML code is rendered or escaped.

    Test both reflected and stored injection points.

Pass Criteria:
All HTML code is properly escaped; no injection or execution occurs.

Fail Criteria:
HTML injected appears rendered or executable.

Screenshots:

    Input with HTML payload

    Resulting rendered page showing injection

🔹 3. Ensure Redirect Only Allows Safe Domain Redirects

Objective:
Prevent open redirect vulnerabilities by restricting redirect targets to trusted domains.

Steps:

    Identify redirect parameters or URL redirect functionality.

    Attempt to redirect to external or malicious domains.

    Test URL encoding, double encoding, and URL obfuscation techniques.

    Verify that redirects outside safe domains are blocked or sanitized.

Pass Criteria:
Redirects only permit whitelisted/trusted domains.

Fail Criteria:
Open redirect allows arbitrary external domain redirection.

Screenshots:

    Requests with malicious redirect parameter

    Application response or redirect behavior

🔹 4. Check Overly Permissive CORS Policy

Objective:
Detect Cross-Origin Resource Sharing (CORS) misconfigurations that allow unauthorized cross-origin access.

Steps:

    Analyze CORS headers (Access-Control-Allow-Origin, Access-Control-Allow-Credentials).

    Test if wildcards (*) or user-controllable origins are allowed.

    Use custom origin headers to test acceptance of unauthorized domains.

    Verify if sensitive endpoints respond to cross-origin requests.

Pass Criteria:
CORS policy restricts origins appropriately; no wildcards or overly permissive settings.

Fail Criteria:
CORS policy allows unauthorized cross-origin requests.

Screenshots:

    Response headers showing permissive CORS settings

    Proof-of-concept cross-origin request success

🔹 5. Test Clickjacking via iframe

Objective:
Check if the application can be embedded in iframes that enable clickjacking attacks.

Steps:

    Attempt to load the application page inside an iframe on a test page.

    Observe if the page loads or is blocked.

    Verify presence of X-Frame-Options or Content-Security-Policy frame-ancestors directives.

    Use developer tools to inspect headers.

Pass Criteria:
Page is not allowed to load in iframe (denied by X-Frame-Options or CSP).

Fail Criteria:
Page loads successfully in iframe, allowing clickjacking.

Screenshots:

    Test page iframe embedding the target page

    Browser console or network tab showing missing anti-framing headers

🔹 6. WebSocket TLS and Origin Validation

Objective:
Ensure WebSocket connections use secure TLS and validate origin to prevent unauthorized access.

Steps:

    Identify WebSocket endpoints.

    Confirm use of wss:// (secure WebSocket) instead of ws://.

    Use tools (e.g., Burp, Wireshark) to analyze handshake and messages.

    Attempt connections from unauthorized origins or non-TLS connections.

    Verify if origin validation rejects unauthorized clients.

Pass Criteria:
WebSocket uses TLS and properly validates origin headers.

Fail Criteria:
WebSocket connections allowed over unencrypted channels or with invalid origins.

Screenshots:

    WebSocket handshake details showing TLS usage

    Attempts and responses from unauthorized origins

🔹 7. Check Sensitive Data in HTML5 Local/Session Storage

Objective:
Detect sensitive data improperly stored in client-side storage mechanisms.

Steps:

    Use browser dev tools to inspect localStorage and sessionStorage.

    Look for storage of sensitive info like tokens, passwords, PII, or session IDs.

    Attempt to extract and use stored data for unauthorized access.

Pass Criteria:
No sensitive data stored client-side; only safe data present.

Fail Criteria:
Sensitive data exposed in client-side storage.

Screenshots:

    Browser storage inspection showing sensitive entries

    Example of extracted sensitive data

✅ Phase 13 – Special Cases & Advanced Security Controls Testing
🔹 1. OAuth2 Security Checks — Detailed Step-by-Step Testing Guide
Objective:

Verify OAuth2 implementation for authorization flaws, token leakage, redirect URI vulnerabilities, and improper scope enforcement.
Step-by-Step Procedure:
Step 1: Identify OAuth2 Flows Used by the Application

    Tools: Burp Suite (Proxy + HTTP history), browser developer tools (Chrome DevTools/Firefox DevTools)

    How:

        Log in to the application normally, intercept HTTP(S) traffic with Burp Proxy.

        In Burp HTTP history, filter for URLs containing /oauth, /authorize, /token, or access_token.

        Examine the parameters:

            If you see response_type=code → Authorization Code flow

            If response_type=token → Implicit flow

            Check if client_id, redirect_uri, scope parameters are present.

        Note down the OAuth endpoints (authorization endpoint, token endpoint).

Step 2: Test Redirect URI Validation

    Goal: Check if redirect URI validation is strict or can be bypassed to redirect to attacker-controlled domains.

    Manual Steps:

        Capture an OAuth authorization request, e.g.:

        GET /oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://app.example.com/callback&scope=openid

        Modify the redirect_uri parameter in Burp Repeater or Intruder with:

            Exact attacker domain: https://evil.com

            URL-encoded attacker domain: https%3A%2F%2Fevil.com

            URL encoding tricks (double-encoding): https%253A%252F%252Fevil.com

            URI with trailing slash: https://app.example.com/callback/../evil.com

            Partial subdomain: https://evil.app.example.com

            Using Unicode homoglyphs or similar-looking domains.

        Send the request and observe:

            Does the server redirect to your attacker domain?

            Does it throw an error?

    Automated Step:

        Use Burp Intruder on redirect_uri with a payload list containing common attacker domains and encoding tricks.

        Analyze responses for redirect status codes (3xx) or error messages.

Step 3: Intercept and Analyze Access Tokens

    Goal: Ensure tokens are not leaked in URLs or insecurely stored.

    How:

        Using Burp Proxy, intercept OAuth responses during login or token exchange.

        Look for access_token or refresh_token in:

            URL query parameters (after # or ?)

            JSON responses

            HTTP headers (Authorization: Bearer)

        In browser DevTools → Application → Storage → check if tokens are stored in localStorage/sessionStorage/cookies.

    Check:

        Tokens should never appear in URLs.

        Refresh tokens should never be accessible via client-side JavaScript (i.e., HttpOnly cookies).

Step 4: Verify PKCE Enforcement (for Authorization Code Flow)

    Goal: Confirm Proof Key for Code Exchange (PKCE) is used to prevent code interception attacks.

    Steps:

        In the authorization request, check for parameters:

        code_challenge=xyz
        code_challenge_method=S256

        If missing, PKCE likely not implemented.

        Attempt to replay an authorization code without providing the correct code verifier:

            Intercept token request with code.

            Modify or remove the code_verifier parameter.

            Send request and check if the token endpoint rejects it.

Step 5: Test Token Expiration and Replay

    How:

        Obtain a valid access token.

        Record the expiry timestamp from the token payload (decode JWT or check token metadata).

        Attempt to use the token after expiry:

            Use Postman or Burp to call protected APIs with expired token.

            Confirm if access is denied.

        Replay the same token multiple times in quick succession:

            Confirm if the token can be used multiple times (this is usually allowed).

        Attempt to use the same refresh token multiple times:

            Confirm if reuse is blocked or allowed.

Step 6: Scope Enforcement Testing

    Goal: Verify token scopes are properly enforced.

    Steps:

        Capture a token with limited scopes (e.g., read).

        Modify token payload (if JWT) to include admin or write scopes:

            Use JWT debugger or Burp extension.

            Re-sign token if weak secret or none algorithm is used.

        Replay request with modified token to access privileged endpoints.

        Verify server denies access for unauthorized scopes.

Step 7: Test Refresh Token Leakage and Security

    Steps:

        Verify refresh tokens are never exposed in URLs or in localStorage.

        Attempt to intercept refresh token in HTTP traffic.

        Use a captured refresh token to obtain new access tokens.

        Test if refresh tokens can be reused multiple times without revocation.

Step 8: Test for Token Replay and CSRF Protections

    Steps:

        Capture an authorization request with a state parameter.

        Remove or modify state value and resend request.

        Confirm if server rejects or accepts request.

        Confirm whether tokens are bound to a specific client or can be used from any origin.

Pass Criteria:

    Redirect URIs only allow exact matches or securely validated.

    Access and refresh tokens never exposed in URLs.

    PKCE enforced on authorization code flow.

    Tokens expire correctly and are revoked after use.

    Scopes strictly enforced on resource access.

    Tokens are securely stored with HttpOnly and Secure flags.

    State parameter protects against CSRF in authorization requests.

Fail Criteria:

    Open redirect in redirect_uri.

    Tokens leaked in URLs or client-accessible storage.

    Missing PKCE or weak code verifier enforcement.

    Expired tokens accepted.

    Scope bypass allowed.

    Tokens accepted with missing/modified state.

Screenshots to Take:

    Modified authorization request with malicious redirect_uri.

    Intercepted token response showing token in URL.

    Token replay requests and server responses.

    Requests with modified state parameter.

    Access to privileged API with tampered token.


