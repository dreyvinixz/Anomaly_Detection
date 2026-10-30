# Etapa 3 — Avaliacao da matriz de confusao do SMA(10)

## Objetivo

A avaliacao deve separar as predicoes do detector (alarme SIM/NAO)
do **ground truth verificado** (ataque/benigno/desconhecido).
Uma matriz 2x2 requer rotulo real binario para todas as janelas
pontuadas, pois considerar "sem ataque informado" como benigno cria
falsos FP, TN, precision, recall e F1 artificialmente.

## Executar

Instale o projeto e execute na raiz do repositorio:

    python -m pip install -e .
    darpa-anomaly evaluate-confusion-week2

Dados reais de entrada:

- reports/week2-1999/data/traffic_60s.csv: 6.424 minutos
  capturados, 8–12/03/1999.
- data/ground_truth/darpa1999_week2_official_attack_starts.csv:
  43 inicios de ataques documentados (EST historico convertido UTC).
- data/ground_truth/week2_intervals_review.csv:
  registro de intervalos validados por revisores (inicialmente vazio).

O algoritmo repete as predicoes com SMA(10) e detector robusto MAD
threshold=4.5, residual_warmup=10, preservando limites de capturas
e janelas causais. A elegibilidade e a classe real devem coincidir
no mesmo minuto UTC.

## Artefatos

Em results/stage3-confusion:

1. evaluation.json: contagens, cobertura, metricas de previsao,
   estado da matriz, e auditoria de proximidade dos inicios.
2. alarm_label_coverage.csv: tabela 3x2 de cobertura.
   Linhas = attack verificado / benigno verificado / desconhecido;
   colunas = alarme / sem alarme. **NAO E MATRIZ DE CONFUSAO 2x2.**
3. official_onset_alert_audit.csv: 43 eventos, minuto do inicio,
   pontuabilidade e correspondencia temporal a +/-0/1/5/10min.
4. onset_proximity_summary.csv: totais por tolerancia.
5. README.md: relatorio interpretativo, populado com o resultado real.
6. confusion_matrix.csv: **so existe quando 100% das janelas
   pontuadas tem rotulo verificado**.

Para rótulos parciais, o JSON pode registrar a contagem TP/FP/FN/TN
**somente do subconjunto verificado**. Isso NAO fornece estimativa
representativa do dataset completo, pois a selecao de casos rotulados
pode ser tendenciosa. As metricas globais continuam null.
Sem nenhum rotulo validado, nao existem contagens de TP/FP/FN/TN.

A avaliacao e restrita a janelas nao aquecidas, enquanto NMSE/MAPE
usam todas as janelas que tem previsao. Isso explica denominadores
diferentes e esta documentado na Parte B.

## Semantica da matriz

              Predito SIM   Predito NAO
Real ATAQUE       TP             FN
Real BENIGNO      FP             TN

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- Specificity = TN / (TN + FP)
- F1 = 2TP / (2TP + FP + FN)
- Accuracy = (TP + TN) / total avaliado

Denominadores nulos produzem valor null e nao zero.
Alarmes em minutos sem rotulo nao se tornam automaticamente FP.
Proximidade ao instante de inicio oficial NAO equivale a TP.

## Fontes e justificativa de cobertura

- MIT Week 2: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html
- Inicios dos 43 ataques:
  https://archive.ll.mit.edu/ideval/docs/detections_1999.html
- 1999 dataset oficial:
  https://www.ll.mit.edu/r-d/datasets/1999-darpa-intrusion-detection-evaluation-dataset
- Ground truth da Etapa 2: docs/GROUND_TRUTH_WEEK2.md

As capturas e os inicios conhecidos nao informam sozinhos as duracoes
exaustivas nem a ausencia de intrusao durante todos os outros minutos.
O arquivo master_identifications.list nao pertence a semana de treino
08–12/03 e nao deve ser alinhado aos cinco PCAPs INSIDE da semana.

## Etapa cientifica pendente

Para publicar a matriz verdadeira, revisar:
(1) segmentos de ataque e limite temporal de cada episodio;
(2) periodos verdadeiramente benignos;
(3) cobertura do sensor INSIDE, IP/protocolo e ataques nao observaveis;
(4) o artigo AVA quanto a definicao de NMSE.
