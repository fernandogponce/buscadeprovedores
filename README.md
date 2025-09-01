# 🔍 Analisador de IPs - Detector de VPN e Tipo de Conexão

## Descrição

Ferramenta avançada para análise investigativa de endereços IP com geração de relatórios HTML interativos, mapa de geolocalização e detecção automática de VPN/Proxy. Desenvolvida especificamente para apoio em investigações policiais e análises forenses.

## 🎯 Características Principais

### 📊 Análise Avançada de IPs
- **Detecção de VPN/Proxy**: Utiliza múltiplas APIs para identificar conexões suspeitas
- **Geolocalização precisa**: Coordenadas GPS com visualização em mapa interativo
- **Classificação de conexão**: Diferencia entre conexões móveis e fixas
- **Análise de risco**: Detecta nós Tor, datacenters e serviços de hospedagem

### 🗺️ Mapa Interativo
- **Visualização geográfica**: Mapa mundo com marcadores coloridos por tipo de ameaça
- **Pop-ups informativos**: Informações detalhadas ao clicar em cada marcador
- **Sistema de cores**:
  - 🟢 Verde: Conexão segura
  - 🔴 Vermelho: VPN/Proxy detectado
  - 🟡 Amarelo: Conexão móvel
  - 🔵 Azul: Status indeterminado

### 📋 Relatórios Detalhados
- **Dashboard HTML**: Interface moderna e responsiva
- **Estatísticas resumidas**: Totais por categoria e país
- **Tabela completa**: Todos os dados organizados e filtráveis
- **Exportação múltipla**: CSV, JSON e Word

### 📄 Geração de Ofícios
- **Automática por provedor**: Cria ofícios requisitórios separados por ISP
- **Modelo padrão**: Baseado na legislação brasileira atual
- **Campos personalizáveis**: Procedimento, prazo, email de resposta
- **Formatação jurídica**: Texto pronto para uso oficial

## 🛠️ Instalação e Configuração

### Pré-requisitos
```bash
# Python 3.6 ou superior
python --version

# Instalar dependências
pip install requests
```

### Download
```bash
# Clone ou baixe o arquivo buscadeprovedoresv1.1.py
# Não requer instalação adicional
```

## 📖 Como Usar

### 1. Execução Básica
```bash
python buscadeprovedoresv1.1.py
```

### 2. Seleção do Modo de Entrada

Ao executar, você verá o menu:
```
ANALISADOR DE IPs COM MAPA INTERATIVO OTIMIZADO
==============================================================
Opções de entrada:
1. Digitar IPs manualmente
2. Carregar de arquivo (um IP por linha)
```

### 3. Formatos de IP Suportados

#### Formato Simples
```
8.8.8.8
1.1.1.1
```

#### IP com Porta
```
8.8.8.8:80
1.1.1.1:443
```

#### Dados Completos (WhatsApp, Telegram, etc.)
```
8.8.8.8:80 em 01/01/2025 às 10:30:00 (UTC-3)
1.1.1.1 443 02/01/2025 14:30 (UTC-3)
```

#### Formatos Flexíveis
```
192.168.1.1:8080 01/12/2024 15:45:30 UTC-3
10.0.0.1 porta 80 data 01/12/2024
```

### 4. Entrada Manual

**Opção 1 - Digitação direta:**
```
Escolha uma opção (1-2): 1

Digite os IPs a serem analisados:
- Um IP por linha
- Digite 'fim' para finalizar

Digite os IPs:
8.8.8.8
1.1.1.1:443
8.8.4.4 53 02/08/2025 14:30:00 UTC-3
fim
```

### 5. Entrada por Arquivo

**Opção 2 - Arquivo de texto:**
```
Escolha uma opção (1-2): 2
Digite o nome do arquivo: ips_para_analisar.txt
```

**Conteúdo do arquivo exemplo (ips_para_analisar.txt):**
```
8.8.8.8
1.1.1.1:443
8.8.4.4:53 em 01/01/2025 às 10:30:00 (UTC-3)
185.199.108.153:80
142.251.132.14 443 15/12/2024 09:15:30 UTC-3
```

## 📊 Interpretação dos Resultados

### Dashboard HTML

O relatório gerado contém:

#### 1. Estatísticas Resumidas
- Total de IPs analisados
- Quantidade de VPN/Proxy detectados
- Conexões móveis vs fixas
- Países e provedores únicos

#### 2. Mapa Interativo
- **Marcadores coloridos** por tipo de risco
- **Pop-ups detalhados** com informações completas
- **Zoom e navegação** para análise detalhada

#### 3. Tabela de Resultados
| Campo | Descrição | Exemplo |
|-------|-----------|---------|
| IP | Endereço IP analisado | 8.8.8.8 |
| Porta | Porta da conexão | 443 |
| Data/Hora | Timestamp da conexão | 01/01/2025 10:30:00 |
| VPN/Proxy | Status de detecção | Detectado / Não detectado |
| Tipo Conexão | Móvel ou Fixa | Móvel |
| País | Localização geográfica | Brasil 🇧🇷 |
| Provedor | ISP ou operadora | Vivo S.A. |

### 🚨 Indicadores de Risco

#### Alto Risco (Vermelho)
- ✅ VPN detectada
- ✅ Proxy ativo
- ✅ Nó Tor identificado
- ✅ Datacenter/Hospedagem

#### Médio Risco (Amarelo)
- ✅ Conexão móvel
- ✅ Localização inconsistente

#### Baixo Risco (Verde)
- ✅ Conexão residencial fixa
- ✅ Sem indicadores suspeitos

## 📄 Geração de Ofícios

### Como Usar

1. **Preencher dados do procedimento** na seção superior:
   - Tipo de procedimento (ex: Inquérito Policial)
   - Número do procedimento (ex: 001/2025)
   - Prazo de resposta (ex: 30 dias)
   - Email para resposta

2. **Selecionar provedor**: Clique no botão correspondente ao ISP desejado

3. **Revisar ofício**: O texto é gerado automaticamente

4. **Copiar ou baixar**: Use os botões para obter o ofício

### Exemplo de Ofício Gerado

```
Senhor Diretor da Vivo S.A.,

Visando instruir o Inquérito Policial nº 001/2025, na qualidade 
de Delegado(a) de Polícia Civil, no exercício das atribuições que 
me conferem os art. 144, § 4º, da CF c/c art. 2º, §2º, da Lei 
12.830/2013, e com fundamento nos arts. 10, §3º e 15, da Lei 
12.965/2014 c/c art. 17-B da Lei 9.613/98 e art. 15 da Lei 
12.850/2013, requisito, no prazo de 30 (trinta) dias, os dados 
cadastrais vinculados ao(s) IP(s):

1. IP: 177.32.45.123, Porta: 443, Data: 15/12/2024, 
   Horário: 14:30:00 (UTC-3)
2. IP: 177.32.45.124, Porta: 80, Data: 15/12/2024, 
   Horário: 15:45:30 (UTC-3)

Adicionalmente, requisito, com base no art. 15, § 1º, da Lei 
nº 12.965/2014, a preservação do conteúdo das comunicações 
privadas e de todos os registros de conexão e de acesso a 
aplicações de internet relacionados ao(s) identificador(es) 
acima mencionado(s), pelo período de 1 (um) ano, a partir da 
data desta comunicação, a fim de viabilizar futura ordem 
judicial para acesso ao seu conteúdo.

A investigação policial é sigilosa (art. 20 CPP) e, por isso, 
o usuário não deve ser notificado acerca das requisições policiais.

Por fim, solicito que a resposta seja encaminhada para o e-mail 
delegado@pc.mt.gov.br.

Atenciosamente,
```

## 🔧 Funcionalidades Avançadas

### Filtros e Busca
- **Filtrar por VPN**: Mostrar apenas IPs com VPN detectada
- **Filtrar por tipo**: Conexões móveis ou fixas
- **Filtrar por país**: Selecionar localização específica
- **Filtrar por provedor**: ISP específico
- **Busca por IP**: Localizar IP específico na tabela

### Exportação de Dados

#### 1. Copiar para Word
```javascript
// Botão: "📋 Copiar TABELA para Word"
// Resultado: Tabela formatada pronta para colar no Word
```

#### 2. Exportar CSV
```csv
IP,Porta,Data,Hora,UTC,Versão,VPN_Proxy,Tipo_Conexão,País,Cidade,Provedor,Organização,AS
8.8.8.8,53,,,IPv4,Não detectado,Fixa,Estados Unidos,Mountain View,Google LLC,Google LLC,AS15169
```

#### 3. Exportar JSON
```json
[
  {
    "ip": "8.8.8.8",
    "porta": "53",
    "país": "Estados Unidos",
    "provedor": "Google LLC",
    "status_vpn": "Não detectado",
    "latitude": 37.4056,
    "longitude": -122.0775
  }
]
```

## 🔍 APIs Utilizadas

### 1. ip-api.com
- **Geolocalização**: Coordenadas GPS precisas
- **Informações de rede**: ISP, organização, AS number
- **Detecção básica**: Proxy, mobile, hosting
- **Limite**: 1000 consultas/hora (gratuito)

### 2. vpnapi.io
- **Detecção VPN**: Algoritmos especializados
- **Análise Tor**: Identificação de nós Tor
- **Detecção Proxy**: Proxies anônimos
- **API Key**: Inclusa no script (limitada)

### 3. OpenStreetMap
- **Mapas**: Visualização geográfica
- **Gratuito**: Sem limitações de uso
- **Responsivo**: Funciona em todos os dispositivos

## ⚠️ Limitações e Considerações

### Limitações Técnicas
- **IPv6**: Funcionalidade limitada em algumas APIs
- **Rate Limiting**: 1.5 segundos entre consultas para evitar bloqueios
- **Precisão**: Geolocalização pode ter margem de erro
- **VPN Detection**: Nem todas as VPNs são detectadas

### Considerações Legais
- **Marco Civil**: Baseado na Lei 12.965/2014
- **Lei de Organizações Criminosas**: Art. 15 da Lei 12.850/2013
- **Sigilo**: Requisições policiais são sigilosas
- **Prazo**: Preservação por 1 ano conforme legislação

### Boas Práticas
- **Verificação cruzada**: Usar múltiplas fontes quando possível
- **Documentação**: Manter registros das análises
- **Atualização**: APIs podem mudar, verificar periodicamente
- **Backup**: Salvar resultados importantes

## 🔒 Segurança e Privacidade

### Processamento Local
- ✅ Todos os dados ficam no seu computador
- ✅ Não há envio de informações para terceiros
- ✅ APIs consultadas apenas para obter dados públicos

### Dados Sensíveis
- ⚠️ Não inclua IPs internos em relatórios
- ⚠️ Mantenha sigilo sobre investigações
- ⚠️ Use conexão segura para consultas

## 📞 Suporte e Contato

Para dúvidas técnicas ou sugestões de melhorias:

- **Polícia Judiciária Civil - MT**
- **Setor de Inteligência Digital**

### Logs de Erro

Em caso de problemas, verifique:

```bash
# Conectividade
ping ip-api.com
ping vpnapi.io

# Dependências Python
python -c "import requests; print('OK')"

# Permissões de arquivo
ls -la buscadeprovedoresv1.1.py
```

## 🆕 Changelog

### v1.1 (Atual)
- ✅ Mapa interativo otimizado
- ✅ Pop-ups informativos detalhados
- ✅ Sistema de cores por tipo de ameaça
- ✅ Geração automática de ofícios
- ✅ Exportação para Word/CSV/JSON
- ✅ Parser flexível de formatos de IP
- ✅ Interface responsiva

### Próximas Versões
- 🔄 Integração com APIs adicionais
- 🔄 Análise em lote de arquivos grandes
- 🔄 Relatórios personalizáveis
- 🔄 Integração com bases de dados locais

---

## 📋 Exemplo Completo de Uso

### Cenário: Análise de IPs do WhatsApp

1. **Exportar dados do WhatsApp** (via WhatsApp Web ou aplicativo)
2. **Extrair IPs** do log de conexões
3. **Criar arquivo** com os IPs:

```
# ips_whatsapp.txt
157.240.23.35:443 em 15/12/2024 às 14:30:15 (UTC-3)
31.13.66.35:80 em 15/12/2024 às 14:30:20 (UTC-3)
157.240.23.36 443 15/12/2024 14:35:00 UTC-3
```

4. **Executar análise**:
```bash
python buscadeprovedoresv1.1.py
# Escolher opção 2
# Informar: ips_whatsapp.txt
```

5. **Aguardar processamento** (1-2 minutos para 3 IPs)

6. **Abrir dashboard** gerado (dashboard_ips.html)

7. **Preencher dados** do procedimento

8. **Gerar ofícios** para Meta/Facebook

9. **Exportar resultados** para anexar ao procedimento

### Resultado Esperado
- 📊 Dashboard completo com mapa
- 📄 Ofício requisitório para Meta
- 📋 Tabela para anexar ao relatório
- 💾 Arquivos CSV/JSON para backup

---

*Ferramenta desenvolvida para apoio investigativo da Polícia Judiciária Civil. Uso restrito a órgãos de segurança pública e investigação criminal.*