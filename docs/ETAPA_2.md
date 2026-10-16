# Etapa 2 — Dataset DARPA 1999 (resultados)

A segunda etapa foi executada integralmente em GitHub Actions, usando
as cinco capturas inside tcpdump da Week 2 (1999).

- [Relatório completo com gráficos, tabela por dia e ressalvas](../reports/week2-1999/README.md)
- [Série de 60 segundos em CSV](../reports/week2-1999/data/traffic_60s.csv)
- [Métricas JSON da execução](../reports/week2-1999/results/metrics.json)
- [Gráfico semanal corrigido, PPS no eixo Y](../reports/week2-1999/figures/traffic_pps_gap_aware.png)
- [Auditoria das capturas e lacunas](../reports/week2-1999/results/capture_validation.json)
- [Workflow da análise integral](../.github/workflows/darpa-week2.yml)
- [Workflow de publicação dos resultados no Git](../.github/workflows/publish-week2-results.yml)

**Resumo:** 7.275.137 pacotes, 6.424 janelas de 60 segundos e 115 alertas
em 6.274 janelas pontuadas (taxa de alertas de 1,833%). MAE de 6,1314 PPS,
RMSE de 12,3259 PPS e máximo de 401,7167 PPS.

Esses alertas ainda não foram cruzados com os rótulos oficiais de ataques;
consequentemente, não representam uma taxa de detecção de ataques.

Origem do snapshot:
https://github.com/dreyvinixz/Anomaly_Detection/actions/runs/38824820433
