# MikroTik-blacklist

A safe, automated script that updates an IP blacklist on your MikroTik router every week.

## Why?

Many blacklist repositories on GitHub provide scripts you schedule to run directly on your router.
This means you’re executing **unreviewed remote code** on a network-critical device every few days — a serious security risk if that code is ever compromised.
A compromised script could turn your router into part of a botnet, leak sensitive information, or disrupt your network.

## How this is different

This solution uses a **one-time installation**:

* You review the script once before installing.
* That exact reviewed code runs every week — no automatic code changes.
* The script **fetches only a plain text list of IP addresses** (IPv4 and IPv6, one per line).
* It parses the file locally, validates every entry, and updates a MikroTik address-list.
* No remote scripts are executed — only static, pre-approved logic runs.

## Security highlights

* **Text-only download**: The remote file contains addresses only, never code.
* **Input validation**: Each line is checked to ensure it’s a valid IP/CIDR before being added.
* **No `:import` usage**: Prevents executing arbitrary code from the download.
* **HTTPS with certificate verification**: Blocks tampering between GitHub and your router.
* **Comment tagging**: Updates only the entries created by this script, leaving your manual rules untouched.

## File format

```
# Example blacklist file
192.0.2.10
203.0.113.0/24
2001:db8::dead:beef
2001:db8:1234::/48
```

* One entry per line.
* IPv4 and IPv6 supported.
* CIDR notation allowed.
* Lines starting with `#` are ignored.

## Quick Start Installation

1. **Download the script**

   * Get the `.rsc` script file from this repository to your local machine.

2. **Review the code**

   * Open the file in a text editor and read it carefully.
   * Confirm it only contains the intended logic and no unexpected commands.

3. **Upload to your router**

   * Use **Winbox**, **WebFig**, or `/tool fetch` to upload the reviewed script file to your MikroTik router.

4. **Install the script**

   * In RouterOS, go to:

     ```
     /system script add name=update-github-blacklist source=[contents of script]
     ```
   * Or use Winbox’s **System → Scripts** menu to paste the code into a new script.

5. **Schedule automatic updates**

   * Add a scheduler to run the script every 7 days:

     ```
     /system scheduler add name=github-blacklist-update interval=7d on-event=update-github-blacklist
     ```

6. **Run manually (optional)**

   * To test immediately:

     ```
     /system script run update-github-blacklist
     ```
