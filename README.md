# Vulnerability Advisory: Broken Access Control / Improper Authorization in Password Change

### Affected Product
- **Name:** User Registration & Login and User Management System With admin panel
- **Vendor Homepage:** [https://phpgurukul.com/user-registration-login-and-user-management-system-with-admin-panel/](https://phpgurukul.com/user-registration-login-and-user-management-system-with-admin-panel/)
- **Affected Version:** V3.3

---

### Project Structure & Vulnerable Location
```text
User Registration and login System with admin panel/
└── loginsystem/
    ├── change-password.php          ← user-side (reported separately)
    └── admin/
        └── change-password.php      ← admin-side (Lines 9-16 vulnerable)
```

- **Vulnerable File:** `/loginsystem/admin/change-password.php`
- **Vulnerable Lines:** Lines 9–16
- **Vulnerable Parameter:** `currentpassword` (POST)
- **Vulnerability Type:** Improper Authorization / Broken Access Control ([CWE-863](https://cwe.mitre.org/data/definitions/863.html))
- **Attack Type:** Remote, Authenticated (requires a valid admin session)

---

### Root Cause
Identical logic flaw to the one present in the user-panel `loginsystem/change-password.php` (reported separately), but affecting the `admin` table. The current-password verification query checks whether the submitted (MD5-hashed) value matches **ANY** row in the `admin` table, rather than being scoped to the currently authenticated admin's own record:

```php
// loginsystem/admin/change-password.php (Lines 9-16)
$oldpassword=md5($_POST['currentpassword']); 
$newpassword=md5($_POST['newpassword']);
$sql=mysqli_query($con,"SELECT password FROM admin where password='$oldpassword'");
$num=mysqli_fetch_array($sql);
if($num>0)
{
$adminid=$_SESSION['adminid'];
$ret=mysqli_query($con,"update admin set password='$newpassword' where id='$adminid'");
```

The `SELECT` statement omits `WHERE id='$adminid'`, so it returns a match for **ANY** admin row's password, not necessarily the logged-in admin's own credential. Only the `UPDATE` is correctly scoped to the session's admin ID.

---

### Difference From Related Reports (CVE-2025-28011 Distinction)
This vulnerability is strictly distinct from **CVE-2025-28011** (which covers SQL Injection on the `currentpassword` parameter in the same file/endpoint):
- **CVE-2025-28011** is an input-sanitization / injection vulnerability where unescaped input allows SQL injection payloads.
- **This vulnerability (CWE-863)** is a pure authorization / business logic flaw. Even if all SQL queries are 100% parameterized with prepared statements and completely immune to SQL injection, this vulnerability **still exists** because the verification query structurally lacks a per-session identity constraint (`WHERE id='$adminid'`). Reviewers must not flag this as a duplicate of CVE-2025-28011.

---

### Proof of Concept (PoC)

1. Log in to the admin panel with known admin credentials (e.g. `admin` / `Test@12345`, as documented in the project's `Readme.txt`).
2. Navigate to **Admin > Change Password** (`/loginsystem/admin/change-password.php`).
3. Submit the Current Password field with the MD5-equivalent plaintext of **ANY** admin account's actual password (in a single-admin deployment this offers limited extra value beyond the admin's own known password, but the flaw generalizes to any deployment with multiple admin accounts sharing the `admin` table):

```http
POST /loginsystem/admin/change-password.php HTTP/1.1
Host: localhost
Cookie: PHPSESSID=<admin_session>
Content-Type: application/x-www-form-urlencoded

currentpassword=<any_valid_admin_password>&newpassword=Hacked999&update=Update
```

4. The application responds `"Password Changed Successfully !!"` and updates the session admin's own password, regardless of whether the submitted "current password" belonged to that specific admin account.

---

### Impact
In multi-admin deployments of this codebase (the schema supports multiple rows in the `admin` table), an admin whose session is compromised (e.g. via XSS, session fixation, or a stolen cookie) can bypass the current-password re-authentication gate by supplying any **OTHER** admin's known password, without knowing their own actual session-owner's password. This weakens defense-in-depth against session-based account-takeover chains. Severity is lower than the user-panel equivalent in single-admin deployments (the shipped default configuration has one admin account), but the underlying code defect is identical and the CWE-863 classification applies equally.

---

### Mitigation
Scope the verification query to the logged-in admin's own row:

```php
$adminid = $_SESSION['adminid'];
$sql = mysqli_query($con, "SELECT password FROM admin WHERE id='$adminid' AND password='$oldpassword'");
```

Use prepared statements regardless of this fix.