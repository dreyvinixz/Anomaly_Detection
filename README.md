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
