# Etapa 5 — Investigação por destino e protocolo (PCAP INSIDE)

Foram relidas as cinco capturas originais do MIT, com verificação de contagens globais e de cada minuto investigado contra a série da Etapa 2.

| ID | Ataque | Destino oficial | IPv4 oficial | SYN PPS 5 min antes | SYN PPS 6 min a partir do início | Destino SYN mais frequente |
|---:|---|---|---|---:|---:|---|
| 17 | satan | marx.eyrie.af.mil | não resolvido | 0.193333 | 29.227778 | 172.16.114.50 |
| 24 | satan | marx.eyrie.af.mil | não resolvido | 1.466667 | 29.497222 | 172.16.114.50 |
| 26 | neptune | pigeon.eyrie.af.mil | 172.16.114.207 | 2.143333 | 30.002778 | 172.16.114.207 |
| 36 | neptune | marx.eyrie.af.mil | não resolvido | 0.806667 | 29.252778 | 172.16.114.50 |

**Interpretação:** a identificação do IP de pigeon (172.16.114.207) é sustentada pelo inventário oficial de hosts de 1999. O destino marx não aparece naquele inventário oficial; publicações acadêmicas independentes permitem relacioná-lo a 172.16.114.50, e o PCAP fornece corroboração adicional. Trata-se de mapeamento secundário, não de um IP presente na tabela de hosts oficiais.

Os números acima mostram metadados de conexões TCP capturadas nos minutos próximos aos inícios, e não a atribuição de sessões a um ataque. Para saber as contagens relativas ao IP pigeon, consultar four_attack_event_evidence.csv.

## Todos os 115 alertas

Cada janela de alerta foi validada contra o PCAP original e possui contagem TCP/UDP/ICMP, flags SYN/ACK/RST/FIN, número de IPs/portas distintos, principais destinos e fenótipo de tráfego.

| Fenótipo de tráfego | Quantidade de alertas |
|---|---:|
| low_rate_deviation | 33 |
| mixed_unresolved | 44 |
| udp_dominated | 38 |

![Taxas SYN em PPS](figures/four_event_syn_pps.png)

![Categorias de triagem](figures/alert_protocol_phenotypes.png)

## Limitações e validade científica

- Os quatro ataques são candidatos temporais, não quatro verdadeiros positivos confirmados.
- Um pico de SYN para um alvo coincide com comportamento suspeito, mas tráfego de fundo também pode contribuir.
- O período analisado (5 min antes, 6 min a partir do início) NÃO representa a duração verificada de cada ataque.
- Os 106 alertas fora de ±5 min dos inícios oficiais não são falsos positivos automaticamente, pois ataques podem continuar.
- Este estudo não identifica integralmente sessões maliciosas, não permite computar TP/FP/F1 definitivos e não deve alegá-los.

## Fontes e reprodutibilidade

- Hosts: https://archive.ll.mit.edu/ideval/docs/hosts_1999.html
- Inícios: https://archive.ll.mit.edu/ideval/docs/detections_1999.html
- Capturas: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html
- Código: src/anomaly_detection/packet_evidence.py
- Workflow: .github/workflows/packet-evidence.yml
- Arquivos: packet_window_features.csv, four_attack_event_evidence.csv, all_115_alert_packet_audit.csv, summary.json e dois PNGs.
- Nenhum payload nem PCAP completo foi incluído no Git.


## Análise confirmatória após correção das flags TCP

A [execução corrigida #38829717225](https://github.com/dreyvinixz/Anomaly_Detection/actions/runs/38829717225)
foi concluída com sucesso. A extração anterior de flags booleanas apresentou
valores SYN/RST zerados por erro de interpretação do campo TShark: essa versão
foi substituída por máscaras de bits sobre o campo hexadecimal tcp.flags
(SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01). Os CSVs e a figura de SYN deste
diretório contêm **somente os resultados corrigidos**.

| MIT ID | Ataque | IP destino corroborado | Tráfego ao destino (6 min) | Pacotes SYN sem ACK ao destino | Portas TCP distintas com SYN | Evidência do vínculo nome-IP |
|---:|---|---|---:|---:|---:|---|
| 17 | SATAN | 172.16.114.50 | 13.543 | 10.463 | 9.999 | Literatura acadêmica + PCAP |
| 24 | SATAN | 172.16.114.50 | 12.378 | 10.055 | 9.997 | Literatura acadêmica + PCAP |
| 26 | Neptune | 172.16.114.207 | 10.740 | 10.242 | 1.024 | Inventário oficial MIT + PCAP |
| 36 | Neptune | 172.16.114.50 | 12.231 | 10.270 | 1.046 | Literatura acadêmica + PCAP |

Os valores de SATAN correspondem a milhares de portas TCP distintas no mesmo
destino, padrão fortemente consistente com sondagem/varredura. Os dois casos
Neptune têm grande número de SYN sem ACK concentrados nos alvos, compatível
com a descrição de ataque por SYN flood. **Isso corrobora a identidade e a
assinatura do evento, mas não prova que todos os pacotes da janela sejam
maliciosos nem fornece o início/fim verdadeiro de cada sessão.**

O campo target_ipv4_official permanece vazio para marx no CSV porque ele
não foi encontrado no inventário oficial de hosts internos de 1999.
O mapeamento marx → 172.16.114.50, agora corroborado empiricamente,
aparece em publicações independentes:

- Computer Networks 45 (2004), pp. 175–193:
  https://citeseerx.ist.psu.edu/document?doi=09d599a09ed0010b650c7b078c52d6780b7ab794&repid=rep1&type=pdf
- Detection of Web-based Attacks through Markovian Protocol Parsing:
  https://citeseerx.ist.psu.edu/document?doi=0ea94147c57398653a5797414986963338248227&repid=rep1&type=pdf

**Triagem dos 115 alertas**: 33 desvios relativos com PPS baixo,
38 janelas com tráfego predominantemente UDP e 44 janelas de tráfego
misto. Essas categorias NÃO são classes benigno/malicioso e os 106
alertas fora da vizinhança temporal dos 43 inícios oficiais continuam
sem rótulo confiável de falso positivo.

A etapa demonstra **evidência técnica de protocolo e destino para os quatro
eventos candidatos**, mas métricas definitivas de precisão, recall, F1
ou taxa de falsos positivos ainda exigem rótulos de sessões/intervalos
ou auditoria independente do tráfego malicioso.
