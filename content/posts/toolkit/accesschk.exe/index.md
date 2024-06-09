---
title: "Accesschk.exe"
date: 2023-02-15T16:55:35+03:00
menu:
  sidebar:
    name: Accesschk.exe
    identifier: accessch.exe
    parent: toolkit
    weight: 10
    
draft: false
---

Access Control and Privilege Escalation: Understanding [Accesschk.exe](https://download.sysinternals.com/files/AccessChk.zip)

Accesschk.exe, part of the Sysinternals Suite, is a command-line utility that checks the access rights of files, registry keys, and other resources in Windows.

Here are some examples of commands to check access rights:

1.  Report effective permissions on a file: `accesschk.exe -e c:\example.txt`
2.  Check explicit permissions on a registry key: `accesschk.exe -k HKEY_LOCAL_MACHINE\SOFTWARE\example`
3.  Check inherited permissions on a service: `accesschk.exe -i -s example`
4.  Check effective permissions on a file for a specific user: `accesschk.exe -u DOMAIN\username c:\example.txt`
5.  Check effective permissions on a process for a specific group: `accesschk.exe -p -uc DOMAIN\groupname example.exe`

Accesschk.exe can also be used in Windows privilege escalation, which involves gaining access to resources or privileges that are not normally available to a user. For instance, you can use the command `accesschk.exe -uwcqv "SYSTEM" *` to check which services are running as the SYSTEM user.

Here are the options that control `accesschk.exe`:

-   `-u`: Shows only the permissions for a specified user or group.
-   `-w`: Shows the owner and their access rights of the object.
-   `-c`: Shows the effective access rights for a user or group, taking into account any deny permissions.
-   `-q`: Suppresses any output other than the access rights information itself.
-   `-v`: Shows the names of all objects that `accesschk.exe` scans.

You can combine these options in various ways to get the specific information you need. For example, `accesschk.exe -uc jsmith c:\windows\system32` shows the effective access rights for the user "jsmith" in the "c:\windows\system32" directory.

Another way to use Accesschk.exe is to identify registry keys and files that have overly permissive access controls. For example, `accesschk.exe -w -accepteula *` checks for all registry keys that are writable by the Everyone group.
