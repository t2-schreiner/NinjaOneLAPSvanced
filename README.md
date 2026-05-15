# NinjaOneLAPSvanced

NinjaOne PowerShell automation that combines a LAPS-style local
administrator password rotation with a graphical local-admin audit
report and a changelog. Additionally a full audit log is written to the machine.

> # Warning
> Never set the scheduled run to automatically remove unautorized Admins on any scope.
>Depending on the configuration you might accidentally lockout legitimate users which were aded to the Administrators group by mistake!


## What the script does

`LAPSvanced.ps1` performs three tasks every time it runs:

1. **LAPS password rotation** – creates (or updates) a managed local
   administrator account, generates a complex random password and
   writes the credentials to NinjaOne custom fields so they can be
   retrieved from the device record.
2. **Local administrator audit (WYSIWYG report)** – enumerates every
   member of the local *Administrators* group and writes a styled HTML
   report to a NinjaOne WYSIWYG custom field. Authorized admins are
   highlighted **green**, unauthorized admins are highlighted **red**.
3. **Alert flag** – when at least one unauthorized admin is detected, a
   checkbox custom field is set to `true` so a NinjaOne condition can
   raise an alarm.

Local user example:
<img width="1785" height="814" alt="image" src="https://github.com/user-attachments/assets/07fff073-3295-4b4e-8b3d-b008212315de" />

Entra ID example:
<img width="1711" height="971" alt="image" src="https://github.com/user-attachments/assets/29bd3e8a-b234-489f-a927-27b93fbb1d87" />

Active Directory example:
<img width="1730" height="845" alt="image" src="https://github.com/user-attachments/assets/469a1cfc-dc67-43cd-b5bf-4d97e0a2a795" />

Change log example:
<img width="959" height="90" alt="image" src="https://github.com/user-attachments/assets/0a4123de-17dd-41f8-8db2-9f84159a6fdc" />


## Required NinjaOne custom fields

| Field name (default)       | Type     | Purpose                                              | Automation permission     |
|----------------------------|----------|------------------------------------------------------|---------------------------|
| `LAPSuser`             | Text     | Stores the managed local admin username              | `WRITE`                 |
| `LAPSpw`             | Secure   | Stores the rotated password                          | `WRITE`                     |
| `LAPSlocalAdminsReport`        | WYSIWYG  | Receives the HTML local-admin report                 | `WRITE`            |
| `LAPSauthorizedLocalAdmins`    | Text     | Comma-separated list of authorized administrators    | `READ`             |
| `LAPSunauthorizedAdminsFound`  | Checkbox | Set to `true` when unauthorized admins are detected  | `WRITE`           |
|`LAPSchangelog`                 |Multi-line| Per-run history of changes performed by the script  | `READ` `WRITE`   |

The script (running as **SYSTEM**) needs write access to all of the
fields above. Field names can be changed at the top of the script.

### Recommended custom field setup

The data fields are recommended to be setup in a dedicated card at the desired device type/role.
<img width="1253" height="534" alt="image" src="https://github.com/user-attachments/assets/afcfd428-fb37-46fb-91c8-d2f1ab3f7f90" />



### Authorized list format

`LAPSauthorizedLocalAdmins` is a plain comma-separated list of accounts
that are allowed to be local administrators on the machine, e.g.:

This field needs to be created as organization custom field with an inheritance set to device. So authorized admins can be managed organizationwide with per device overides.

<img width="176" height="127" alt="image" src="https://github.com/user-attachments/assets/a89ec11d-b393-4233-8272-db87c1584b74" />


```
randomadmin, DOMAIN\CLIENT-TIER-ADMINS, locadm
```

Comparison is case-insensitive and matches both the short account name
(`locadm`) and the fully qualified name (`DOMAIN\CLIENT-TIER-ADMINS`). For
Entra ID principals (which often appear only as a raw SID), an entry
may also be the SID (`S-1-12-1-...`) or the decoded Entra Object ID
GUID. The following entries are always treated as authorized so they
never trigger false positives:

* the LAPS managed account itself (`LAPSadmin` by default)
* `Domain Admins` and `Enterprise Admins`

#### Optional typed prefixes

Each entry may be tagged with a case-insensitive prefix that documents
its intent and groups it under a labelled sub-section in the report
card. Matching is unaffected &mdash; the prefix is stripped before the
value is compared against name/SID/Entra Object ID.

| Prefix   | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| `role:`  | Entra ID directory role principal (by Object ID or name)                |
| `group:` | Entra ID or Active Directory group (by Object ID or name)               |
| `user:`  | Individual user principal (by UPN, Object ID, or DOMAIN\name)           |
| `sid:`   | Explicit security identifier                                            |
| `name:`  | Explicit account name (e.g. `DOMAIN\user`)                              |
| *(none)* | Untagged &mdash; rendered under "Other"; matched the same way as above  |

Example:

```
role:62e90394-69f5-4237-9190-012177145e10,
group:11111111-2222-3333-4444-555555555555,
user:user@domain.local,
DOMAIN\CLIENT-TIER-ADMINS
```

> **Entra ID directory roles.** This script audits and (optionally)
> cleans up the *local* Administrators group on the device. It cannot
> enumerate or modify membership of Entra ID directory roles &mdash; that
> information lives in Entra ID and must be managed there. Adding
> `role:<oid>` entries simply tells the script to treat principals with
> that Object ID as authorized when they appear locally.

### Triggering an alarm

In NinjaOne create a *Custom Field Condition* on
`LAPSunauthorizedAdminsFound` with operator `is checked` and attach the
desired alert / notification channel.

<img width="668" height="113" alt="image" src="https://github.com/user-attachments/assets/8ba7c217-73a2-4527-a9d4-97dc0c7306ca" />


 <img width="640" height="386" alt="image" src="https://github.com/user-attachments/assets/38ec7ad7-ad5f-4f49-a9aa-05de5898719e" />

## Configuration

The most common settings are at the top of `LAPSvanced.ps1`:

```powershell
$NewAdminUsername     = 'LAPSadmin'  # name of the managed local admin account
$PasswordLength       = 20           # total password length

$CF_LapsUsername      = 'LAPSuser'
$CF_LapsPassword      = 'LAPSpw'
$CF_AdminsReport      = 'LAPSlocalAdminsReport'
$CF_AuthorizedAdmins  = 'LAPSauthorizedLocalAdmins'
$CF_UnauthorizedFlag  = 'LAPSunauthorizedAdminsFound'
$CF_Changelog         = 'LAPSchangelog'

# --- Changelog ---
# A short, human-readable history of every run is appended to the
# multi-line text custom field defined by $CF_Changelog. The
# automation must have READ + WRITE permission on this field.
$ChangelogEnabled    = $true
$ChangelogCategories = @(
    'PasswordRotation'      # LAPS password rotated
    'RemovedAdmin'          # account removed from local Administrators
    'DisabledNativeAdmin'   # built-in Administrator (RID 500) disabled
    'UnauthorizedDetected'  # unauthorized admin still present
    'Error'                 # unhandled exception
)
$ChangelogMaxLines   = 500  # oldest entries are trimmed first
```

## Deployment in NinjaOne

Add the following **script variables** to the automation:

   | Variable name                     | Type     | Values / notes                                                                 |
   |-----------------------------------|----------|--------------------------------------------------------------------------------|
   | `Mode`                            | Dropdown | `All Functions`, `Report Only`, `Password Rotate` (default = `All Functions` when empty) |
   | `RemoveUnauthorizedAdminsScope`   | Dropdown | `Disabled`, `Local Only` *(default)*, `Local and Domain`, `All` &mdash; controls which kinds of unauthorized principals are removed from the local Administrators group |
   | `DisableNativeAdmin`              | Checkbox | *(default = on)* &mdash; when on, an enabled built-in `Administrator` account (RID 500) is automatically disabled. The built-in is never *removed* from the local Administrators group, only disabled (CIS Benchmark recommendation). |

<img width="446" height="277" alt="image" src="https://github.com/user-attachments/assets/f4bd05b0-7abe-4f0b-acc3-64647fd14dde" />


   The script reads them via `$env:Mode`, `$env:RemoveUnauthorizedAdminsScope`
   and `$env:DisableNativeAdmin`. If `Mode` is omitted the script runs
   all functions. Removal and the built-in disable step only fire when
   the selected mode includes the audit (`All Functions` or
   `Report Only`).

<img width="543" height="775" alt="image" src="https://github.com/user-attachments/assets/a03d184b-9f02-40a8-96c4-9e3562500c47" />



   **What each removal scope does**

   <img width="545" height="776" alt="image" src="https://github.com/user-attachments/assets/b439be80-4b4b-4126-a71c-c8e7af4776e7" />

   | Scope                 | Removes from local Administrators                                  | Reports only (still flagged in WYSIWYG) |
   |-----------------------|--------------------------------------------------------------------|------------------------------------------|
   | `Disabled`            | nothing                                                            | every unauthorized principal             |
   | `Local Only` *(default)* | local SAM accounts/groups that are not on the authorized list   | unauthorized AD, Entra ID, Microsoft Account, and Unknown principals |
   | `Local and Domain`    | local + Active Directory accounts/groups                           | unauthorized Entra ID, Microsoft Account, and Unknown principals |
   | `All`                 | local + AD + Microsoft Account + **resolved Entra ID user accounts only** | Entra ID groups, directory roles, raw SID / Object ID only members, and Unknown-scope principals (never auto-removed) |

   The local enumeration always covers all scopes &mdash; AD users/groups
   and Entra ID identities that are direct members of the local
   Administrators group are visible in the report regardless of the
   removal scope, and the `unauthorizedAdminsFound` alert fires for any
   unauthorized principal in any scope. The privileged AD groups
   (`Domain Admins`, `Enterprise Admins`, `Schema Admins`) and the
   managed LAPS account are always protected from automatic removal.

   **Entra ID safety net.** Even with `RemovalScope = All`, the cleanup
   step will only auto-remove an Entra ID principal when it is
   positively identified as a real, named user account (i.e. Windows
   resolved its short name to something other than a SID, an Entra
   Object ID, or any other GUID). Entra ID groups, directory-role
   principals (Global Administrator, Azure AD Joined Device Local
   Administrator, Cloud Device Administrator) and "raw SID / OID only"
   members &mdash; typically principals that have never signed in on
   the device, so the OS could not translate them &mdash; remain in the
   group and are surfaced as `Report only` in the report. They must be
   handled manually (or in Entra ID itself).


   **Built-in Administrator (RID 500)**

<img width="544" height="511" alt="image" src="https://github.com/user-attachments/assets/d31bdaab-ded9-40f4-87ac-af6a7e854290" />

   The native local `Administrator` account is treated separately:

   * It is **never removed** from the local Administrators group
     (removing RID 500 is unsupported by Windows and breaks safe-mode
     recovery).
   * It is considered *authorized* only when it is **disabled**.
   * When `DisableNativeAdmin = on` (default), an enabled built-in
     Administrator is automatically disabled. While disabled, it is
     shown as authorized in the report.
   * When `DisableNativeAdmin = off`, an enabled built-in Administrator
     is reported as unauthorized and the `unauthorizedAdminsFound`
     alert fires &mdash; the operator must either flip the variable or
     disable the account manually.




   **Reporting**

   The WYSIWYG report uses NinjaOne's native styling primitives
   (`card`, `info-card`, `stat-card`, `tag`, table row classes
   `success` / `danger` / `warning`) so it visually integrates with the
   agent UI. It is grouped into one card per scope (Local, Active
   Directory, Entra ID, Microsoft Account, Unknown), each labelled with
   a Font Awesome icon. Per-row "Action" tags show whether each
   unauthorized principal will be removed (`WILL REMOVE`), was just
   removed (`REMOVED`), is reported only (`REPORT ONLY` &mdash; out of
   the configured removal scope), or &mdash; for the built-in
   Administrator only &mdash; will be / was just disabled
   (`WILL DISABLE`, `DISABLED`) or should be disabled manually
   (`SHOULD DISABLE`, when `DisableNativeAdmin = off`).
4. Run it as **System** on a recurring schedule (e.g. daily) against
   the desired device policy.
5. (Optional) Create a condition on `unauthorizedAdminsFound` to be
   notified when an unexpected local administrator appears.
