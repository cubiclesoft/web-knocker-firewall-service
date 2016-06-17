Web Knocker Firewall Service
============================

A web-based service written in pure PHP for Linux servers that opens protected TCP and UDP ports in response to encrypted requests from a correctly configured client for a limited but renewable time period.

Features
--------

* IPv4 and IPv6 support.
* Dynamic iptables chains and rules.
* Can run multiple instances of the server on a single host.
* Can run multiple instances of the client on a single host.
* Optionally sends notification e-mail(s) whenever a client successfully opens a port on the server.
* Server controlled ports and timeouts limit what a client can do.
* Two-way communication.  Clients don't just send an encrypted data packet and hope that it worked.
* And much, much more.  See the official documentation for a more complete feature list.
* Also has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your envrionment.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

More Information
----------------

Documentation, examples, and official downloads of this project sit on the Barebones CMS website:

http://barebonescms.com/documentation/cloud_backup/
