# Anomaly Detection — DARPA 1999

Detector offline para tráfego da segunda semana (8 a 12 de março de 1999)
do DARPA 1999, usando somente os cinco arquivos **inside tcpdump**.
A granularidade é **60 segundos** e os gráficos mostram **pacotes por
segundo (PPS)**. Dados: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html

## Instalar no Ubuntu / WSL2

~~~bash
sudo apt-get update && sudo apt-get install -y tshark gzip python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
~~~

## Executar

~~~bash
darpa-anomaly download --data-dir data/raw
darpa-anomaly preprocess --data-dir data/raw --series data/processed/traffic_60s.csv
darpa-anomaly detect --series data/processed/traffic_60s.csv --out-dir results
darpa-anomaly plot --detections results/detections.csv --out-dir results/figures
~~~

Alternativamente, após baixar os arquivos:

~~~bash
darpa-anomaly run --data-dir data/raw --out-dir results
~~~

Também pode ser invocado via python -m anomaly_detection.

## Pipeline e saídas

1. Baixar cerca de 800 MB de arquivos compactados diretamente do MIT.
2. Descompactar em streaming para o TShark e extrair timestamp/comprimento.
3. Concatenar cronologicamente, agregando pacotes e bytes por 60 segundos.
4. Salvar data/processed/traffic_60s.csv, incluindo PPS=packets/60.
5. Aplicar previsão EWMA causal e detecção por MAD robusto.
6. Exportar results/detections.csv, anomalies.csv, metrics.json e
   figures/traffic_pps.png (eixo Y em PPS).

Os dados são lidos individualmente, sem gerar um PCAP mesclado gigante.
Arquivos brutos e resultados não são versionados.

## Testes

~~~bash
python -m unittest discover -s tests -v
~~~

A metodologia e limitações estão em docs/METHODOLOGY.md.

**Status:** baseline inicial. Os ataques oficiais ainda não estão
integrados como ground truth e a avaliação no dataset completo ainda
precisa ser executada. Nenhuma métrica real do DARPA foi inventada.


## Processamento integral no GitHub Actions

O workflow [DARPA 1999 Week 2 - full offline analysis](.github/workflows/darpa-week2.yml)
usa uma VM temporária Ubuntu 24.04 sem depender do computador local.
Ele inicia automaticamente no primeiro push da configuração na branch
feat/mvp-60s-ewma. Depois de integrado à main, novas execuções poderão
ser iniciadas em **Actions > DARPA 1999 Week 2 > Run workflow**.

Etapas automatizadas:
1. Instalar TShark e dependências Python e executar testes unitários.
2. Baixar cinco arquivos inside.tcpdump.gz de segunda a sexta.
3. Verificar integridade de cada gzip e registrar SHA-256.
4. Processar os PCAPs em streaming, em buckets UTC de 60 segundos.
5. Auditar source_day, timestamps, cronologia e PPS = pacotes/60.
6. Calcular EWMA/MAD, estatísticas e gráfico com eixo Y em PPS.
7. Publicar o Artifact darpa-week2-60s-<run_id> com:
   - data/processed/traffic_60s.csv
   - results/capture_validation.json
   - results/sha256sums.txt
   - results/detections.csv e results/anomalies.csv
   - results/metrics.json e results/figures/traffic_pps.png

Os arquivos PCAP compactados NÃO são incluídos no Artifact nem em commits.
Artefatos expiram após 14 dias. A fonte do MIT precisa aceitar downloads
no ambiente GitHub-hosted; caso contrário o job mostrará o erro no log.
A comparação com o ground truth oficial dos ataques continua pendente.


## Etapa 2 — Resultados empíricos versionados (DARPA 1999 Week 2)

A execução real no GitHub Actions foi concluída com sucesso: **7.275.137
pacotes**, **6.424 janelas de 60 segundos** e **115 anomalias sinalizadas**
em **6.274 janelas avaliadas**. MAE = 6,1314 PPS e RMSE = 12,3259 PPS.
Os oito testes unitários foram aprovados.

**Documentação científica com tabelas, gráficos e ressalvas:**
[Etapa 2 — relatório e dados](reports/week2-1999/README.md)
([índice](docs/ETAPA_2.md)).

Os CSVs, gráficos PNG, estatísticas JSON, checagens de integridade e
auditoria temporal são versionados em reports/week2-1999/ pela automação
[Publish Week 2 results](.github/workflows/publish-week2-results.yml).
O arquivo traffic_pps_gap_aware.png evita linhas artificiais atravessando
períodos sem captura. Os dados brutos compactados não são versionados.

**Interpretação importante:** 115 alertas não equivalem a 115 ataques.
A correspondência com o ground truth documentado pelo MIT permanece
pendente e será tratada na etapa seguinte.
