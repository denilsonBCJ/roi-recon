# ROI Recon — Smart Recon Pipeline

Pipeline de reconhecimento automatizado para bug bounty / pentest autorizado, que encadeia:

**`gau` + `waybackurls`** (coleta de URLs históricas) → **scoring por ROI** (heurísticas de valor) → **`httpx`** (verificação de vida + fingerprint) → **re-scoring** → **`nuclei`** (scan de templates nas melhores URLs vivas).

O objetivo é não jogar `nuclei` em dezenas de milhares de URLs cruas, e sim filtrar e priorizar os alvos com maior probabilidade de retorno antes de rodar os scanners mais pesados.

> ⚠️ Use apenas contra domínios para os quais você tem autorização explícita (programas de bug bounty / VDP / pentest contratado). O script não valida escopo — isso é responsabilidade de quem executa.

---

## Requisitos

| Dependência | Versão sugerida | Finalidade |
|---|---|---|
| Python | 3.8+ | Executa o orquestrador |
| Go | 1.21+ | Necessário para instalar as ferramentas abaixo via `go install` |
| [`gau`](https://github.com/lc/gau) | latest | Coleta de URLs (Wayback, AlienVault OTX, Common Crawl, URLScan) |
| [`waybackurls`](https://github.com/tomnomnom/waybackurls) | latest | Coleta de URLs do Wayback Machine |
| [`httpx`](https://github.com/projectdiscovery/httpx) | latest | Probing HTTP (status, título, tecnologias) |
| [`nuclei`](https://github.com/projectdiscovery/nuclei) | v3+ | Scanner de templates |

O script só usa a biblioteca padrão do Python (`os`, `re`, `json`, `subprocess`, `concurrent.futures`, etc.) — **não há dependências de pip**.

---

## Instalação

### 1. Instale o Go (se ainda não tiver)

```bash
# Linux (exemplo via apt)
sudo apt update && sudo apt install -y golang-go

# Ou baixe a versão mais recente em https://go.dev/dl/
```

Garanta que `~/go/bin` está no seu `PATH`:

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### 2. Instale as ferramentas externas

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 3. Baixe/atualize os templates do nuclei

Na primeira execução o `nuclei` costuma baixar os templates automaticamente, mas é bom garantir que estão atualizados:

```bash
nuclei -update-templates
```

### 4. Verifique que os binários estão acessíveis

```bash
which gau waybackurls httpx nuclei
```

Se algum não aparecer, confirme que `~/go/bin` está no `PATH` da sessão atual do terminal.

### 5. Baixe o script

Salve o arquivo `roi_recon.py` (ou o nome que você deu a ele) em uma pasta de sua preferência. Não é necessário instalar nada via `pip`.

---

## Uso

Execute diretamente com Python 3:

```bash
python3 roi_recon.py
```

O script vai pedir o alvo interativamente:

```
[?] Digite a URL/domínio: exemplo.com
```

Pode ser informado como `exemplo.com`, `www.exemplo.com` ou `https://exemplo.com` — o script normaliza automaticamente (remove `www.`, força `https://` para parsing, extrai apenas o host).

Ao final, ele cria uma pasta `scan_<dominio>_<timestamp>/` com todos os artefatos da execução.

### O que o script faz, em ordem

1. **Checagem de dependências** — confirma que `gau`, `waybackurls`, `httpx` e `nuclei` estão instalados e resolvíveis no PATH (ou em `~/go/bin`, `~/.local/bin`, `/usr/local/bin`).
2. **Coleta paralela** — roda `gau --subs` e `waybackurls` ao mesmo tempo, normaliza e deduplica todas as URLs encontradas.
3. **Scoring pré-httpx** — aplica heurísticas (parâmetros presentes, extensões promissoras vs. estáticas, palavras-chave "quentes" no path, padrões de alto valor como `/api/`, `/admin`, `/graphql`, parâmetros sensíveis como `token`, `redirect`, `id` etc.) e filtra só as URLs com score mínimo.
4. **`httpx`** — verifica quais dessas URLs estão vivas, captura status code, título e tecnologias detectadas.
5. **Re-scoring pós-httpx** — soma bônus por status code (200/401/403 valem mais que 404), por palavras no título (`admin`, `swagger`, `dashboard`, `staging`...) e por tecnologia detectada (`graphql`, `wordpress`, `laravel`...).
6. **Seleção de alvos para o nuclei** — separa alvos de "alto valor" (score alto, ou URLs de API/admin/login/billing) dos demais, respeitando os limites configurados, para não estourar tempo de execução.
7. **`nuclei`** — roda nos alvos selecionados com tags focadas em ROI (`exposures`, `misconfig`, `default-login`, `takeover`, `files`, `panels`, `cves`, `tech`, `token-spray`) e severidades `critical,high,medium`, excluindo tags intrusivas (`intrusive`, `fuzz`, `dos`, `network`).
8. **Resumo final** — gera `summary.json` e `summary.txt` com contagem de URLs em cada etapa e caminho de todos os arquivos gerados.

### Interrompendo a execução

`Ctrl+C` é tratado de forma limpa (`SIGINT`) e encerra o script com uma mensagem, sem deixar subprocessos pendurados de forma descontrolada.

---

## Arquivos gerados (dentro de `scan_<dominio>_<timestamp>/`)

| Arquivo | Conteúdo |
|---|---|
| `gau.txt` / `waybackurls.txt` | Saída bruta de cada ferramenta de coleta |
| `all_urls.txt` | União normalizada e deduplicada de todas as URLs coletadas |
| `roi_urls_pre_httpx.txt` | URLs filtradas por score mínimo, antes de verificar se estão vivas |
| `httpx_alive.jsonl` | Saída JSONL bruta do `httpx` |
| `alive_urls_post_httpx.txt` | URLs confirmadas vivas, já re-ranqueadas |
| `alive_ranked_post_httpx.json` | Mesmas URLs vivas, com score, status, título e tech detectada |
| `nuclei_targets.txt` | Lista final de alvos enviados ao `nuclei` |
| `nuclei_targets_ranked.json` | Mesma lista, com metadados de score |
| `nuclei_results.txt` | Achados do `nuclei` |
| `summary.json` / `summary.txt` | Resumo da execução (contagens + caminhos dos arquivos) |

---

## Configuração / Ajustes finos

Os principais parâmetros ficam no topo do script, em `CONFIG`:

- **`HTTPX_TIMEOUT_SECONDS`** / **`NUCLEI_TIMEOUT_SECONDS`** — tempo máximo de cada fase (padrão: 20 min e 40 min).
- **`MAX_URLS_PRE_HTTPX`**, **`MAX_URLS_PRE_NUCLEI`**, **`MAX_URLS_PRE_NUCLEI_HIGH_VALUE`** — limites de quantidade de URLs em cada etapa, para controlar tempo total de execução.
- **`NUCLEI_TAGS`** / **`NUCLEI_SEVERITIES`** — quais categorias e severidades de template o `nuclei` deve rodar.
- **`HOT_PATH_KEYWORDS`**, **`HOT_PARAMS`**, **`HIGH_VALUE_PATTERNS`**, **`TECH_BONUS`**, **`TITLE_BONUS_PATTERNS`** — heurísticas de pontuação; ajuste conforme o perfil dos programas que você costuma testar.

Basta editar essas constantes diretamente no arquivo `.py` antes de rodar.

---

## Solução de problemas

- **`Dependências faltando`** — confira `which gau waybackurls httpx nuclei` e se `~/go/bin` está no `PATH` do shell usado para rodar o script (não só do `.bashrc`, mas da sessão atual).
- **`nuclei` sem achados** — normal em alvos bem protegidos; considere revisar `NUCLEI_TAGS`/`NUCLEI_SEVERITIES` ou ampliar `MAX_URLS_PRE_NUCLEI`.
- **Execução muito longa** — reduza `MAX_URLS_PRE_HTTPX` e `MAX_URLS_PRE_NUCLEI`, ou aumente o `min_score` passado a `filter_roi_urls` dentro de `main()`.
- **Rate limiting / bloqueios do alvo** — o `nuclei` já roda com `-rl 20` (rate limit) e `-c 20` (concorrência); reduza esses valores no comando se o alvo estiver bloqueando o scan.