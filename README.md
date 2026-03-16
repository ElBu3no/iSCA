# iSCA
<p align="center">
  <img src="iSC.png" width="500">
</p>

## Usage

### 1. Clone the repository

```bash
git clone https://github.com/SEUUSUARIO/isca.git
cd isca
```

---

### 2. Install dependencies

Certifique-se de ter as ferramentas necessárias instaladas:

* `subfinder`
* `assetfinder`
* `httpx`
* `gau`
* `waybackurls`
* `katana`
* `qsreplace`
* `curl`
* `jq`

---

### 3. Configure targets

Adicione os domínios que deseja analisar no arquivo `targets.txt`.

Example:

```text
example.com
target.com
company.com
```

---

### 4. Configure GitHub Token (optional)

Para habilitar busca por **secrets em repositórios GitHub**, configure seu token:

```bash
export GITHUB_TOKEN="your_token_here"
```

---

### 5. Run iSCA

Execute o scanner:

```bash
./isca.sh
```

---

### 6. Results

Os resultados serão organizados automaticamente em pastas:

```
hunt_target/

recon/
  subs.txt
  alive.txt

urls/
  urls_clean.txt

params/
  params.txt

vulns/
  xss.txt
  sqli.txt
  redirects.txt
  graphql.txt

secrets/
  secrets_found.txt

infra/
  git_exposed.txt
  buckets.txt
```

---

### Example

```bash
./isca.sh
```

Output:

```
🔥 SCANNER AVANÇADO: example.com

[+] Enumerating subdomains...
[+] Discovering URLs...
[+] Extracting parameters...
[+] Testing vulnerabilities...

✅ Scan completed
```

---

### Recommended Usage

iSCA é ideal para:

* Bug Bounty reconnaissance
* Web attack surface discovery
* API discovery
* Initial vulnerability triage
* Offensive security research
