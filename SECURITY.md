# Security

airbnb-check is a read-only tool, but it parses data sent by devices on a network you do not control, so bugs matter.

- Found a vulnerability (for example a way a malicious device on the LAN could run code, inject terminal escape sequences, or make the tool contact other hosts)? Please use GitHub's **private vulnerability reporting**: Security tab > "Report a vulnerability" on https://github.com/junowoz/airbnb-check.
- Anything that is not sensitive (false positives, wrong device types, crashes) can go in a normal GitHub issue.

The tool only reads from your own private subnet, never logs in, never writes to devices, and uses only the Python standard library. Details are in the README.
