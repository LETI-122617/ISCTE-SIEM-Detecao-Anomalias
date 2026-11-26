# Deteção de Anomalias e Redução de Falsos Positivos em Ambientes SIEM

**Modelação Estatística de Ataques de Força Bruta em Splunk Enterprise**

Projeto desenvolvido no âmbito da unidade curricular de **Segurança em Redes e Sistemas de Informação** do **Mestrado em Engenharia de Telecomunicações e Informática (ISCTE-IUL)**.

---

## Objetivo

Os Centros de Operações de Segurança (SOC) enfrentam elevados volumes de falsos positivos gerados por regras estáticas, conduzindo à fadiga de alertas. Por outro lado, abordagens recentes baseadas em *Large Language Models* (LLMs) introduzem latências elevadas e custos operacionais difíceis de sustentar em tempo real.

Este projeto implementa e valida um **motor de deteção estatístico nativo em SIEM**, recorrendo à linguagem **SPL (*Search Processing Language*)** do *Splunk Enterprise*. O modelo calcula continuamente a média móvel ($\mu$) e o desvio padrão ($\sigma$) das falhas de autenticação SSH numa janela deslizante de 30 minutos, definindo um limiar adaptativo:

$$X_t > \mu + k \cdot (\sigma + \epsilon)$$

com $k = 3$ e constante de estabilização $\epsilon = 1$, eliminando a necessidade de treino externo ou infraestrutura de Inteligência Artificial dedicada.

---

## Arquitetura Laboratorial

O ambiente de testes foi configurado em rede local no modo *Bridged* (`192.168.1.0/24`), assegurando comunicação direta entre os três nós:

| Função | Sistema Operativo | Endereço IP | Papel no Laboratório |
| :--- | :--- | :--- | :--- |
| **Atacante** | Kali Linux | `192.168.1.109` | Execução de ataques de força bruta SSH com *Hydra* |
| **Vítima** | Ubuntu Server/Desktop | `192.168.1.75` | Serviço *OpenSSH* + *Splunk Universal Forwarder* v9.1.2 |
| **SIEM Central** | Windows (Host) | `192.168.1.82` | *Splunk Enterprise* à escuta na porta TCP `9997` |

---

## Configuração e Replicação

### 1. Motor SIEM (Windows)
1. No *Splunk Enterprise*, ativar a receção de dados na porta TCP `9997` (*Settings > Forwarding and receiving > Configure receiving*).
2. Criar uma regra de entrada na Firewall do Windows para permitir tráfego TCP na porta `9997`.

### 2. Agente de Recolha de Logs (Ubuntu)
Instalar o *Splunk Universal Forwarder* (a opção `-4` força IPv4 caso existam falhas de encaminhamento IPv6) e configurar o reencaminhamento de `/var/log/auth.log`:

```bash
# Transferência e instalação do Universal Forwarder
wget -4 -O splunkforwarder.deb "[https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b6b9c8185839-linux-2.6-amd64.deb](https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b6b9c8185839-linux-2.6-amd64.deb)"
sudo dpkg -i splunkforwarder.deb

# Arranque inicial e aceitação da licença
sudo /opt/splunkforwarder/bin/splunk start --accept-license

# Apontar para o SIEM central e monitorizar o registo SSH
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.1.82:9997
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -sourcetype syslog -index main
sudo /opt/splunkforwarder/bin/splunk restart
```

---

## Regra Estatística em Splunk SPL

A pesquisa seguinte agrega as falhas de autenticação SSH em intervalos de 1 minuto e calcula a *baseline* sobre os 30 minutos anteriores. O parâmetro `current=false` garante a exclusão do instante atual $X_t$ do cálculo histórico, evitando que o pico anómalo mascare o próprio limiar no momento da deteção.

```spl
index=main sourcetype=syslog "Failed password"
| timechart span=1m count as falhas_atuais
| streamstats current=false window=30 avg(falhas_atuais) as media_movel, stdev(falhas_atuais) as desvio_padrao
| fillnull value=0 media_movel, desvio_padrao
| eval epsilon = 1
| eval k = 3
| eval limiar = media_movel + (k * (desvio_padrao + epsilon))
| eval alerta_disparado = if(falhas_atuais > limiar, "SIM (Ataque Forca Bruta)", "NAO (Ruido Normal)")
| table _time, falhas_atuais, media_movel, desvio_padrao, limiar, alerta_disparado
```

---

## Cenários de Ataque (Kali Linux)

### Teste de Validação Inicial (8 palavras-passe)
```bash
echo -e "123456\npassword\nadmin\nqwerty\nroot\n12345678\n123456789\ntest" > senhas_falsas.txt
hydra -l root -P senhas_falsas.txt ssh://192.168.1.75 -t 4
```

### Cenário 1: Ataque Volumétrico
```bash
hydra -l root -P /usr/share/wordlists/fasttrack.txt ssh://192.168.1.75 -t 4
```

### Cenário 2: Ataque Furtivo (*Low & Slow*)
```bash
hydra -l root -P /usr/share/wordlists/fasttrack.txt ssh://192.168.1.75 -t 1 -W 15
```

---

## Resultados Experimentais

Os cenários principais totalizaram **121 janelas de 1 minuto** (60 minutos no ataque volumétrico e 61 minutos no ataque *Low & Slow*).

| Cenário / Abordagem | Minutos | TP | FN | FP | TN | FPR | Precisão | Recall | Especificidade | F-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dinâmico: Validação Inicial** | 61 | 1 | 0 | 0 | 60 | 0,00% | 100,00% | 100,00% | 100,00% | 100,00% |
| **Dinâmico: Cenário 1 (Volumétrico)** | 60 | 4 | 2 | 0 | 54 | 0,00% | 100,00% | 66,67% | 100,00% | 80,00% |
| **Dinâmico: Cenário 2 (*Low & Slow*)** | 61 | 0 | 15 | 0 | 46 | 0,00% | N/A | 0,00% | 100,00% | 0,00% |
| **Dinâmico: Total Combinado (Cen. 1 e 2)** | **121** | **4** | **17** | **0** | **100** | **0,00%** | **100,00%** | **19,05%** | **100,00%** | **32,00%** |
| Limiar Estático (`> 3` falhas/min) | 121 | 7 | 14 | 0 | 100 | 0,00% | 100,00% | 33,33% | 100,00% | 50,00% |

### Principais Conclusões
* **Deteção imediata sem falsos positivos:** No ataque volumétrico (312 falhas em 6 minutos, pico de 85 falhas/min), o modelo disparou alerta no primeiro minuto com 100% de precisão e 0,00% de FPR. A entrada dos picos na janela elevou o limiar até `91,49`, originando 2 falsos negativos nos minutos finais.
* **Comprovação da contaminação da *baseline*:** No cenário *Low & Slow* (média de 2,00 falhas/min durante 15 minutos), o limiar subiu gradualmente de `3,00` para `8,01` sem gerar alertas, exigindo 31 minutos após o término do ataque para regressar ao patamar base.
* **Melhorias futuras:** Exclusão de instantes já sinalizados da janela deslizante, substituição do desvio padrão pelo Desvio Absoluto da Mediana (MAD) e utilização de janelas sazonais de longo prazo.

---

## Estrutura do Repositório

```text
ISCTE-SIEM-Deteccao-Anomalias/
├── README.md
├── dados/
│   ├── Ataque_Low_&_Slow_(O_desafio_furtivo).csv
│   ├── Ataque_Volumétrico_(Ruído).csv
│   └── Teste_Inicial.csv
├── relatorio/
│   ├── figuras/
│   │   ├── Ataque Low & Slow.png
│   │   ├── Ataque Volumétrico.png
│   │   ├── diagrama_pesquisa.png
│   │   ├── grafico_limiar.png
│   │   ├── grafico_teste_inicial.png
│   │   └── logo_iscte.png
│   ├── Deteção_de_Anomalias_e_Redução_de_Falsos_Positivos_em_Ambientes_SIEM.pdf
│   └── main.tex
├── revisao_sistematica/
│   ├── articles.xls
│   └── data_extraction.xls
└── scripts/
    └── gerar_grafico_limiar.py
```

---

## Autores

* **Tomás Cerveira** (122617)
* **Alexandre Duarte** (122657)
* **Lara Machado** (122655)
* **Eduardo Real** (122608)

**Docentes:** Daniel Pesqueira Morgado e Daniel Maximino Caçador
