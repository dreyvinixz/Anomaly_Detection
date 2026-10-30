# Entrega B — Janela deslizante, SMA(10), NMSE/MAPE e alarmes

Este módulo **não substitui** o detector EWMA/MAD histórico das Etapas 2–5.
Ele usa a saída existente da Parte A:
[traffic_60s.csv](../reports/week2-1999/data/traffic_60s.csv),
com observações de pacotes/segundo (PPS) por minuto na Week 2 DARPA 1999.

## Rodar com dados reais da Parte A

Após python -m pip install -e . :

    darpa-anomaly part-b --series reports/week2-1999/data/traffic_60s.csv --out-dir results/part-b

Alternativamente:

    python -m anomaly_detection.part_b --series reports/week2-1999/data/traffic_60s.csv

Testes:

    python -m unittest discover -s tests -v

Os artefatos são predictions.csv (cada minuto com previsão/resíduo/score),
alarms.csv (apenas alertas) e metrics.json (erros de previsão,
contagens de alarmes e estado da avaliação supervisionada). Nenhuma
captura PCAP bruta é necessária, pois o CSV de PPS está versionado.

## Requisito 1 — janela deslizante de 10

Para prever PPS no minuto t, são usados exclusivamente os dez valores
observados nos minutos t-10 a t-1. A amostra corrente não participa
do cálculo da própria previsão. Minutos ausentes e limites entre capturas
reiniciam a janela. Minutos de zero tráfego inseridos explicitamente na
preparação da Parte A são valores válidos. Há 10 minutos iniciais
sem previsão depois de cada reinicialização.

## Requisito 2 — SMA (Simple Moving Average)

    yhat[t] = (y[t-10] + ... + y[t-1]) / 10

O preditor é causal, determinístico e gera a previsão antes de incorporar
o dado observado no minuto t. O residual é e[t] = y[t] - yhat[t].

Alarmes: calcula-se um score robusto sobre o residual atual, usando
somente os resíduos anteriores. O centro é a mediana, a escala é
max(1.4826 * MAD, 0.5 PPS), e há alarme quando o score supera 4.5.
Há mais 10 resíduos de aquecimento para o score, após a previsão ficar
disponível. Resíduos sinalizados não contaminam o histórico MAD, mas
o tráfego observado segue atualizado na SMA. Estes limiares são escolhas
operacionais, NÃO parâmetros otimizados com rótulos da semana.

## Requisito 3a — NMSE e MAPE

Calculados em *todas as janelas com previsão* (inclusive o período de
aquecimento apenas dos alarmes), com as fórmulas documentadas:

    NMSE = sum((y[t]-yhat[t])**2) / sum((y[t]-mean(y))**2)
    MAPE = 100 * mean(abs((y[t]-yhat[t])/y[t])) para y[t] != 0

NMSE é indefinido quando a variância da série observada é zero, sendo
emitido como null. O MAPE exclui explicitamente as observações com
y=0, cuja quantidade é registrada no JSON. Se todas forem zero, o
MAPE também é null. O artigo de apoio da turma (AVA) pode adotar
outra normalização de NMSE: é necessário confrontar sua equação.

## Requisito 3b — matriz de confusão

Uma matriz TP/FP/FN/TN é válida **somente com rótulos binários completos**
para cada minuto efetivamente pontuado. O programa NÃO considera
"todos os minutos fora do início de ataques" benignos.

Forneça um CSV separado com cabeçalho:

    window_start_utc,is_attack
    1999-03-08T13:20:00+00:00,0
    1999-03-08T13:21:00+00:00,1

Linhas acima são apenas exemplo de FORMATO, não rótulos oficiais.
O usuário deve fornecer a classificação validada 0/1 para **todas**
as janelas elegíveis (is_warmup=0), sem duplicações ou timestamps fora
da série. O mesmo CSV pode incluir os minutos de aquecimento, ignorados
na contagem. Execute:

    darpa-anomaly part-b --labels caminho/rotulos_validados.csv

Se os rótulos cobrirem todos os minutos pontuados, serão produzidos
confusion_matrix.csv e as métricas accuracy/precision/recall/specificity/F1
em metrics.json. As linhas da matriz são a classe REAL e as colunas
são a PREDIÇÃO (alarme sim/não). Sem rótulos, a matriz será null e
não haverá CSV de matriz. Rótulos parciais provocam erro explícito.

**Atenção às fontes do MIT:** a página detections_1999.html oferece
os inícios dos 43 ataques da segunda semana de TREINAMENTO (8–12/03/1999),
não os intervalos de todos os ataques nem rótulos de cada minuto.
O arquivo master_identifications.list está associado à identificação de
ataques de outro período (registros desde 29/03/1999) e não pode ser
aplicado automaticamente a esta série de 8–12/03/1999.
Mesmo a coincidência de horário com um ataque não prova que o alarme
foi causado por tráfego malicioso.

Fontes:
- https://archive.ll.mit.edu/ideval/docs/detections_1999.html
- https://archive.ll.mit.edu/ideval/files/master_identifications.list
- https://www.ll.mit.edu/r-d/datasets/1999-darpa-intrusion-detection-evaluation-dataset

## Critérios de qualidade

- Previsão sem vazamento temporal (teste de não-lookahead).
- Reinício da janela de dez em lacunas e mudanças de captura.
- Tráfego zero, variância zero e rótulos incompletos tratados.
- CSV e JSON gerados deterministicamente, sem dados sintéticos
  apresentados como avaliação real dos ataques.
