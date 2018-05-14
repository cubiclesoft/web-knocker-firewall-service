Web Knocker Firewall Service
============================

A web-based service written in pure PHP for Linux servers that opens protected TCP and UDP ports in response to encrypted requests from a correctly configured client for a limited but renewable time period.

This software is for Linux system administrators who are serious about network security.  Web Knocker Firewall Service (WKFS) takes your [elegant iptables rules](http://cubicspot.blogspot.com/2016/06/elegant-iptables-rules-for-your-linux.html) to a whole different level without introducing weaknesses in the IP stack.  WKFS has been running successfully in CubicleSoft production environments since June 2016 without any issues.

[![Donate](https://cubiclesoft.com/res/donate-shield.png)](https://cubiclesoft.com/donate/)

Features
--------

* IPv4 and IPv6 support.
* Dynamic iptables chains and rules.
* Can run multiple instances of the server on a single host.
* Can run multiple instances of the client on a single host.
* Optionally sends notification e-mail(s) whenever a client successfully opens a port on the server.
* Port access is renewable.  The PHP client takes advantage of this by attempting to renew twice during the access period.
* Server controlled ports and timeouts limit what a client can do.
* Two-way communication with pre-established encryption keys.  Clients don't just send an encrypted data packet and hope that it worked.
* Standard CubicleSoft dual-encryption.
* Clients can be installed as system services via the included [Service Manager](https://github.com/cubiclesoft/service-manager) binaries.  Windows, Mac, and Linux support.
* Reasonable defenses against various attacks such as replay attacks.
* Also has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your environment.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

Why You Need WKFS
-----------------

* Block rogue connection attempts to critical system services such as SSH, private e-mail servers, and the like.  Russia, China, and North Korea run bots that automatically probe the edges of networks looking for weaknesses.
* Allows time-limited traffic to critical system services from authorized dynamic/roaming IPs without setting up a VPN.  Or you have a VPN but want another layer of security.
* Relies on standard, battle-hardened web technologies such as Apache, Nginx, and PHP.  Classical libpcap-based port knocking or newer single-packet authorization (SPA) solutions inject early into the network stack _before_ iptables, which merely exchanges one security risk for another more serious one.
* Comes with officially supported client software for Windows, Mac, and Linux.

Getting Started
---------------

Download or clone this project.  Upload the 'server' subdirectory to a relatively unguessable location on your Linux-based web server.

Make sure you have the command-line (CLI) version of PHP installed for your Linux distribution (e.g. 'apt install php-cli').  The WKFS installer is written in PHP and therefore requires PHP to be somewhere on the system to function.

From a command-line/shell session on the server, run:

`php install.php`

You will be asked a series of questions that will configure the service and then install and run it.  Firewall/iptables rules _will be modified_ when the WKFS service starts.  As a result, it is highly recommended to have a working recovery plan just in case access to the server is lost.  Two possible options are to have a console/virtual console handy OR switch temporarily from an INPUT DROP policy to an ALLOW policy in case things go horribly wrong.

Once the server portion is set up, put the 'client' subdirectory somewhere on the client (e.g. your computer) and, from a command-line, run:

`php install.php`

During the installation, the client installer will ask for the encryption keys (key1, iv1, key2, iv2) and HMAC signing key (sign) and the server URL where 'index.php' is located.  Copy the keys from the server installation screen and calculate the appropriate URL.  Once the connectivity test passes, the configuration is saved and the client service is optionally installed and started.  It can, of course, be manually run.

To unblock the ports manually or to debug server issues, run the client from the command-line directly:

`php run.php`

On the server side of things, running 'iptables-save' and 'ip6tables-save' will show the current firewall rules including the Web Knocker Firewall Service rules.  Once everything looks good, lock down the server if you switched INPUT from DROP to ACCEPT earlier and then gain a little extra peace of mind with fewer ports open to the world.

How It Works
------------

The client and server share dual encryption keys and a HMAC signing key.  Think of it as a permanently established pre-negotiated SSL session.  When a client wants to open a port, it first makes an information query to identify what ports for which protocols can be opened, how long they can be opened for, and what the server sees as the client IP address.  Stopping a man-in-the-middle (MITM) attack is quite difficult (if not impossible) to begin with but that's not exactly the objective here.  The objective is to keep out all of the automated scripts that are just hammering away at the open ports all day long.  The client's IP address plus a timestamp prevents replay attacks, which is probably more than sufficient for most purposes.

When a query is made by the client, it always uses the CubicleSoft dual encryption, packetization method.  The block size of the request is 512 bytes and the total request size averages around 1,034 bytes - approximately 50% overhead.  If a request is made every 10 minutes, approximately 150KB of data will be sent by the client daily to maintain one or more open ports.  Data to be sent is JSON encoded, prefixed with the size, a HMAC is appended using the signing key, the result is wrapped in random bytes using a CSPRNG padded to the nearest 512 bytes, encrypted twice, and then Base64 encoded using the safe encoding mechanism.

On the server side, the 'index.php' file reverses the procedure to decode, decrypt, and then verify the received data.  If any errors occur, a HTTP error code is emitted and additional information may or may not be available - usually nothing beyond the HTTP error code is available.  If no errors occur and a valid API action was requested, the server responds with an encrypted data packet of its own.

When the request in the data packet is to open one or more ports, 'index.php' opens a TCP connection to the running server started by 'server.php' and passes along the packet information.  'index.php' is running under the web server user, which is probably something like 'www-data' and, of course, cannot make firewall changes.  'server.php', on the other hand, is running as a system service as the root user.  Incoming localhost TCP connections (default is port 33491) send JSON encoded data to the server that specifies which port(s) to open for a specific IP address and for how long along with a shared secret (via 'config.php') that affords some basic protection.  The server responds according to the information received and, upon success, returns when the applied firewall rules will expire.  When the server opens a port (renewals don't count), it will also send notification e-mails if it is configured to do so.

Security Analysis
-----------------

In standard SSL notation, the protocol in use is probably:

`SYSCSPRNG_NA_WITH_AES_2X_4096_CBC_SHA`

CBC mode is irrelevant here - ECB could have been used - since the packetization method described in the previous section mitigates all known (BEAST, etc).  CBC is good for extra mixing, but that's all.  The use of the SHA-1 hash for HMAC is more for compatibility than anything else but HMAC-SHA-1 is still considered to be secure.  Although, if someone can get past the encryption bits to get to the hash, they probably stole your configuration file which contains the encryption keys AND your HMAC signing key, so it doesn't matter.  It's probably much easier to find another way to make a request to 'server.php' via an application vulnerability in the other software running on the web server than to try to break the encryption/signing bits.

Remember all of this is to simply stop automated attack tools by closing the ports that are open to the world that already have their own security mechanisms built in.  Most automated attack tools give up when they don't see an open port and move onto their next target.

Someone may point out that a web knocker has one serious problem:  If the web server is down, it won't work.  In my experience, 98% of the time the web server is down, SSH is also inaccessible due to either heavy CPU load or other irregular reasons (e.g. a poorly written script encounters an unexpected network outage and spawns thousands of processes) and only a remote reboot of the system resolves the multitude of issues involved.  I've only ever occasionally been able to access such systems or already had an active SSH connection to the box - and, even in those cases, I've found that it is still simpler and more efficient to reboot to correct the immediate performance problem and then resolve the core issue that triggered the performance problem after the system comes back up rather than try to do both simultaneously.
