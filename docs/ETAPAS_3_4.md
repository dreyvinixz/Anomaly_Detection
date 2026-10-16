# Etapas 3 e 4 — Validação e sensibilidade (DARPA 1999 Week 2)

Este estágio compara o detector EWMA/MAD aos **43 horários oficiais
de início de ataques** publicados pelo MIT e investiga 27 combinações de
hiperparâmetros. Os resultados são gerados de forma reprodutível, diretamente
dos arquivos de 60 segundos já versionados.

## Fonte de rótulos e interpretação

- Fonte oficial: https://archive.ll.mit.edu/ideval/docs/detections_1999.html
- CSV transcrito: [data/ground_truth/darpa1999_week2_official_attack_starts.csv](../data/ground_truth/darpa1999_week2_official_attack_starts.csv)
- Campos por evento: ID, data, horário de início, destino, ataque.
- O horário da lista está no relógio da simulação (EST, UTC-05:00 em março
  de 1999). O script converte com America/New_York e documenta UTC.
- Referência da captura: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html
  — registros de captura começam às 08h locais / 13h UTC.
- **Os rótulos listam os inícios dos ataques, não suas durações completas.**
  Logo, não há fundamento para rotular TODAS as outras janelas como benignas.

## Protocolo de avaliação

Para cada um dos 43 eventos:

1. Converter início EST em UTC e alinhar à janela de 60 segundos que o contém.
2. Confirmar a existência de janela na captura INSIDE daquele dia.
3. Distinguir janela pontuável de janela durante o warmup.
4. Verificar se há alerta EWMA/MAD a ±0, ±1, ±5, ±10 e ±30 janelas
   em torno do início oficial, limitado à mesma captura.
5. Exportar o instante, PPS, score e distância do alerta mais próximo.

**Correspondência temporal NÃO equivale a detecção confirmada.**
Um alerta próximo pode ser coincidência, e um ataque duradouro pode causar
alertas afastados do início. Um ataque em warmup não fornece evidência de
verdadeiro negativo; tampouco podemos classificar como falso positivo
todo alerta sem início de ataque nas proximidades.

A auditoria classifica cada um dos 115 alertas como próximo ou não próximo
ao início conhecido, **não** como TP ou FP definitivos. Calcular precisão,
recall e F1 requer intervalos reais, validação por IP de destino/protocolo
ou rótulos exaustivos de janelas/pacotes.

## Experimentos de sensibilidade

Grade pré-definida (sem otimizar com base nos rótulos da semana):

| Parâmetro | Valores |
|---|---|
| EWMA alpha | 0.1, 0.2, 0.4 |
| Threshold MAD | 3.0, 4.5, 6.0 |
| Warmup | 15, 30, 60 janelas |
| Histórico de resíduos | 120 (fixo) |
| Piso da escala | 0.5 PPS (fixo) |
| Reinício após lacuna | 5 min (fixo) |
| Total | 27 experimentos |

Métricas: MAE (PPS), RMSE (PPS), volume e taxa de alertas, inícios de ataque
temporalmente próximos dos alertas (±5 min) e contagem de alertas sem
correspondência de início documentado. A semana 2 é o conjunto de teste
exploratório; **não** confundir seleção de parâmetros nessa mesma semana
com generalização ou validação out-of-sample.

## Executar e gerar os arquivos

Sem download adicional de PCAP (já temos a série na main):

~~~bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m anomaly_detection.evaluate_week2
~~~

A automação [evaluate-week2.yml](../.github/workflows/evaluate-week2.yml)
executa a grade em Ubuntu no GitHub Actions e publica os resultados em
[reports/week2-1999/stage3-4/](../reports/week2-1999/stage3-4/).

Saídas automáticas:
- README.md: relatório técnico com números computados (sem valores fictícios).
- summary.json: SHA-256 das entradas, comparações e desenho experimental.
- official_attack_onset_matches_5min.csv: evento a evento.
- alerts_start_proximity_audit.csv: auditoria dos 115 alertas.
- onset_tolerance.csv: análise ±0/1/5/10/30 min.
- hyperparameter_grid.csv: tabela dos 27 experimentos.
- figures/attack_onsets_pps.png: ataques, alertas e série em PPS.
- figures/sensitivity_prediction_error_pps.png: MAE/RMSE em PPS.
- figures/sensitivity_thresholds.png: taxas de alertas e proximidade temporal.

## Próximo nível de validação

Para identificar TP/FP confirmados, precisaríamos associar os ataques a
fluxos/pacotes dos alvos, considerar duração e ataques de baixo volume.
Uma alternativa é analisar os fluxos originários das capturas INSIDE ou usar
rotulações de sessões confiáveis, explicitando seu grau de cobertura.

A lista de 43 inícios documentados, por si só, **não** justifica métricas de
classificação supervisionada das 6.424 janelas.


## Resultado medido em 15/10/2026

A [execução na nuvem](https://github.com/dreyvinixz/Anomaly_Detection/actions/runs/38828048119)
aprovou os testes e reproduziu o snapshot original da Etapa 2:

- 43 horários oficiais integrados e presentes em períodos capturados;
- 38 janelas iniciais efetivamente pontuadas (5 em warmup);
- 4 eventos com alerta a ±5 minutos do início oficial (4/38 inícios pontuáveis);
- 9 janelas de alerta perto de algum início e 106 não associadas a essa janela;
- 27 configurações executadas e tabelas/gráficos de sensibilidade publicados.

Com alpha=0.2 e warmup=30, threshold=4.5 produz 115 alertas e 4
eventos temporalmente próximos; threshold=3.0 produz 280 alertas e
12 eventos próximos. Isso NÃO estabelece melhor precisão, pois alertas
adicionais podem ser legítimos e o dataset não tem rótulos de
intervalo completos nessa tabela.

**Comparabilidade:** MAE e RMSE foram medidos nas janelas pontuadas.
Configurações com warmup diferente avaliam subconjuntos diferentes,
logo diferenças entre warmups não devem ser interpretadas isoladamente
como melhoria de previsão.

A interpretação central permanece: foi calculada cobertura de proximidade
temporal, e **não** uma taxa de detecção confirmada de intrusões.
