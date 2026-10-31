# Fontes secundarias de intervalos — DARPA 1999 treino Week 2

O MIT lista **43 inicios oficiais** mas nao fornece duracoes completas nesta tabela:
https://archive.ll.mit.edu/ideval/docs/detections_1999.html

Charles R. Haag, *An Artificial Immune System-Inspired Multiobjective Evolutionary
Algorithm with Application to the Detection of Distributed Computer Network
Intrusions*, AFIT/GCS/ENG/07-05 (2007), Tabela 4 e Apendice B:
https://www.researchgate.net/publication/221506722_An_Artificial_Immune_System-Inspired_Multiobjective_Evolutionary_Algorithm_with_Application_to_the_Detection_of_Distributed_Computer_Network_Intrusions

O autor examinou 16 eventos dos 43 por filtragem de pacotes INSIDE usando
Ethereal (antecessor do Wireshark), com IP/protocolo, tempos e numeros de
pacote. Explicitou que a delimitacao pode ser imprecisa e nem todo o
ataque e visivel nos pacotes. A sua tabela e prova de **atividade suspeita
associada** a alguns eventos, NAO rotulacao oficial exaustiva.

## Catalogo integrado

Foram transcritos **15 eventos** como `candidate` em
`data/ground_truth/week2_intervals_review.csv` e mantidos em formato
de consulta em `data/ground_truth/week2_literature_candidates.csv`.
Convertidos de EST historico (UTC-05) para UTC com offset explicito.
Fim registrado como a marca de segundo observada +1s (fim exclusivo).
Esse arredondamento nao representa certeza de limite exato.
Os intervalos *nao* geram automaticamente is_attack=1.

**O 16o evento, ID 25, foi explicitamente EXCLUIDO:** a Tabela 4 da
dissertacao posiciona um evento de portsweep por volta de 09:33 de
11/03, enquanto a tabela oficial do MIT situa o ID 25 às 10:50:11
(portsweep) e o ID 24 às 09:33:17 (SATAN). O Apendice B tambem
apresenta identificacoes divergentes. E necessario reconciliar o
evento com pacote e destino antes de fornecer identificador confiavel.

Outra limitacao: a dissertacao descreve `marx` e
`www.eyrie.af.mil` de modo inconsistente para alguns ataques;
nao presumir que sejam o mesmo alvo sem verificar IP e hora no PCAP.

## Escopo da confirmacao por PCAP

O novo comando `python -m anomaly_detection.verify_week2_pcap`
audita **somente os eventos 17/26/36**, cuja evidencia adicional
ja aparece em `reports/week2-1999/stage5-packet-evidence/`.
A tarefa aceita os arquivos INSIDE das capturas de quarta, quinta
e sexta-feira sem salvar pacotes individuais no repositorio, e
exporta metadados e limites observados do trafego TCP SYN entre
os enderecos indicados no estudo.

O comando confirma atividade de rede e confronta a literatura,
**nao** confirma automaticamente malicia, duracao completa nem
rotulos de trafego benigno. O criterio de revisao nao e apenas
ter um IP ou estar proximo no tempo: e preciso identificar sessao,
protocolo/porta, origem, alvo, possivel trafego concorrente,
e evidencias de pacotes ou logs de exploracao.

## Tráfego benigno

O MIT declara como sem ataques as semanas **1 e 3** de treinamento:
https://www.ll.mit.edu/r-d/datasets/1999-darpa-intrusion-detection-evaluation-dataset

Essas semanas podem formar um **controle negativo independente**,
avaliado separadamente para estimar alarmes em dados de fundo.
Isso nao autoriza rotular como benignos os minutos sem ataque
conhecido da **semana 2**. Portanto, sem intervalos benignos da
semana 2 validados, nao se calculam TP/FP/FN/TN globais da semana 2.

## Proximos passos de revisao

1. Reexecutar auditoria de PCAPs e confrontar timestamps/contagens com
   Haag, MIT e a auditoria Stage5. Resolver discrepancias de nomes/IP.
2. Verificar os 15 intervalos individualmente e delimitar sessoes
   atribuidas especificamente aos ataques; promover apenas trechos
   revisados e justificados para `verified`.
3. Conseguir ground truth independente da ausencia de ataques para
   os minutos benignos, nao extrapolar a partir dos 43 inicios.
4. Executar novamente `darpa-anomaly evaluate-confusion-week2`.
