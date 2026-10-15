# Metodologia — versão inicial

Fonte oficial: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html

Os arquivos de segunda a sexta são as capturas INSIDE do DARPA 1999,
semana de treinamento 2. Não usar as capturas OUTSIDE por engano.

## Pré-processamento

Ferramentas: Python >= 3.10, gzip, TShark, matplotlib. Cada arquivo
é lido em streaming: gzip -dc | tshark -r - -T fields -e frame.time_epoch
-e frame.len -E separator=, -E quote=n.

Cada pacote com timestamp t pertence à janela UTC
floor(t / 60) * 60. Por janela somamos pacotes e bytes.
PPS = pacotes / 60. Arquivo de saída: traffic_60s.csv, com
window_start_utc, packets, bytes_total, pps e bytes_per_second.

As cinco capturas são concatenadas logicamente por ordem cronológica;
não usamos concatenação binária de PCAP. Lacunas curtas dentro de uma
captura podem ser zero; intervalos grandes ou entre capturas são
desconhecidos, não são imputados como zero. A semana contém períodos de
paralisação da coleta, documentados na fonte oficial.

## Detecção

Predição causal: EWMA[t] = alpha * observed[t-1] + (1-alpha) * EWMA[t-1].
Erro[t] = observed[t] - predicted[t]. Estimamos mediana e MAD em
uma janela de resíduos anteriores não sinalizados, com escala robusta
max(1.4826 * MAD, 0.5 PPS). Marcamos anomalia se o desvio absoluto do
erro à mediana dividido pela escala for maior que 4.5.

Parâmetros padrão: alpha=0.2, threshold=4.5, warmup=30,
history=120, reset_gap_minutes=5. Após lacunas longas, reiniciar estado.
A janela corrente não entra na estimativa usada para pontuá-la.

Saídas: detections.csv, anomalies.csv, metrics.json e traffic_pps.png.
Os resultados estatísticos são calculados apenas após processar o dataset.
Não afirmamos precisão/recall/F1 sem rótulos de ataques integrados e
alinhamento explícito de fuso horário. O detector univariado de PPS pode
ignorar ataques de baixo volume e a EWMA pode adaptar-se a ataques longos.
