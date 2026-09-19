# Improper Authorization / Broken Access Control in Password Change (Admin Panel)

- **Researcher:** Shailendra Mourya ([CyberShailendra](https://github.com/CyberShailendra1))

- **Contact:** cybershailendra1@gmail.com

- **Product:** User Registration & Login and User Management System With admin panel

- **Vendor:** https://phpgurukul.com/user-registration-login-and-user-management-system-with-admin-panel/

- **Version:** V3.3

- **Vulnerability Type:** CWE-863: Incorrect Authorization (Broken Access Control)

- **Vulnerable File:** `loginsystem/admin/change-password.php` (Lines 9-16)

- **Vulnerable Parameter:** `currentpassword` (POST)


---

### Project Structure & Vulnerable Location
```text
User Registration and login System with admin panel/
└── loginsystem/

    ├── change-password.php        ← user-side (reported separately)
    
    └── admin/
    
        └── change-password.php      ← admin-side (Lines 9-16 vulnerable)
```

### Description & Root Cause

In `loginsystem/admin/change-password.php`, the application fails to tie the current-password validation query to the authenticated administrator's session ID (`$_SESSION['adminid']`). 

```php
// loginsystem/admin/change-password.php lines 9-16
$oldpassword=md5($_POST['currentpassword']); 
$newpassword=md5($_POST['newpassword']);
$sql=mysqli_query($con,"SELECT password FROM admin where password='$oldpassword'");
$num=mysqli_fetch_array($sql);
if($num>0)
{
$adminid=$_SESSION['adminid'];
$ret=mysqli_query($con,"update admin set password='$newpassword' where id='$adminid'");
```

The `SELECT` query checks if the provided `currentpassword` matches any record in the `admin` table. If the database contains multiple admin accounts and the attacker submits the password of any other administrator, the check evaluates to true. The subsequent `UPDATE` query then changes the password for the current session's `adminid`.

---

### Distinction from CVE-2025-28011

This issue is not a duplicate of **CVE-2025-28011**:
- **CVE-2025-28011** covers SQL Injection caused by concatenated inputs in `currentpassword`.
- **This report** covers a logic/authorization flaw (CWE-863). Even if the code uses prepared statements and eliminates SQL injection completely, the validation query still lacks the `WHERE id='$adminid'` constraint and remains vulnerable.

---

### Reproduction Steps (PoC)

1. Sign in to the admin panel (`/loginsystem/admin/`).
2. Go to **Change Password** (`/loginsystem/admin/change-password.php`).
3. Send a POST request where `currentpassword` is set to the password of any existing admin account in the database:

```http
POST /loginsystem/admin/change-password.php HTTP/1.1
Host: target-host
Cookie: PHPSESSID=<valid_admin_session>
Content-Type: application/x-www-form-urlencoded

currentpassword=TargetAdminPassword&newpassword=NewPassword123!&update=Update
```

4. The query returns a match from the `admin` table, and the application updates the password of the active session's admin account.

---

### Impact

Re-authentication controls exist to prevent unauthorized changes when a session is hijacked (via stolen session tokens, XSS, or local browser access). Because this check is not bound to the session owner's account, an attacker can bypass the re-authentication prompt using any valid admin password across the system to gain persistence over the hijacked account.

---

### Remediation

Bind the current-password check to the session user:

```php
$adminid = $_SESSION['adminid'];
$stmt = $con->prepare("SELECT id FROM admin WHERE id=? AND password=?");
$stmt->bind_param("ss", $adminid, $oldpassword);
$stmt->execute();
$result = $stmt->get_result();

if($result->num_rows > 0) {
    // proceed with update
}
```