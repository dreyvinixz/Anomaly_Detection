# Auditoria PCAP dos intervalos candidatos da Week 2

A execucao do GitHub Actions https://github.com/dreyvinixz/Anomaly_Detection/actions/runs/41147956979/artifacts/13021653283 terminou com SUCESSO e
releu as capturas INSIDE de quarta, quinta e sexta-feira. O checksum
SHA-256 dos 3 arquivos coincide exatamente com o snapshot versionado,
e cada captura foi reconciliada com o total de pacotes da Parte A.

| MIT ID | Ataque | Pares IP perto do evento | SYN sem ACK | SYN dentro do candidato | Portas distintas |
|--:|---|--:|--:|--:|--:|
| 17 | SATAN | 10.593 | 10.445 | 10.434 | 9.999 |
| 26 | Neptune | 10.401 | 10.240 | 9.221 | 1.024 |
| 36 | Neptune | 10.381 | 10.240 | 10.203 | 1.024 |

O par de IP de SATAN #17 e Neptune #36 esta baseado em bibliografia
secundaria e corroboração do projeto; o IP 172.16.114.50 NAO foi
obtido no inventario oficial para o hostname marx. O par de Neptune
#26 utiliza o alvo 172.16.114.207 do inventario MIT, alem do atacante
identificado na dissertacao de Haag.

## Divergencias temporais concretas

- **ID 17**: primeira SYN compativel 17:02:09.281560 UTC e ultima
  17:04:35.188960, enquanto o intervalo de literatura cadastrado e
  [17:02:18,17:04:34) UTC. Foram observadas 11 SYN perto, mas
  fora deste intervalo candidato.
- **ID 26**: primeira SYN compativel 16:04:12.478387 UTC e ultima
  16:07:37.365197, versus candidato [16:03:51,16:07:17).
  Foram observadas **1.019 SYN** perto, mas fora do intervalo
  candidato. Assim, o limite final publicado NAO cobre toda a
  atividade SYN observada no par de IP, e requer revisao.
- **ID 36**: primeira 16:20:11.992216 e ultima 16:23:36.731178
  UTC, versus candidato [16:20:10,16:23:36). Foram observadas
  37 SYN fora do intervalo candidato.

Esses intervalos de evidencia foram coletados com margem de
2 minutos em torno do segmento da dissertação. Os primeiros e
ultimos pacotes aqui nao determinam os limites reais da atividade
maliciosa completa; podem incluir trafego nao malicioso, e
atividades fora da margem nao foram cobertas pela contagem.

**Conclusao:** os tres eventos possuem corroboracao de trafego
TCP SYN em pares de IP e horarios consistentes, mas **nenhum
intervalo foi promovido automaticamente a ground truth `verified`**.
Sem review humano/atribuição de sessoes, durações exaustivas e
periodos benignos da mesma semana, TP/FP/FN/TN globais seguem
indisponiveis. Os dados deste diretório sao evidencia para
revisao cientifica, nao avaliacao supervisionada final.

Fonte institucional da dissertacao:
https://scholar.afit.edu/etd/3111/

Fonte consultada para horarios e metodologias:
https://www.researchgate.net/publication/221506722_An_Artificial_Immune_System-Inspired_Multiobjective_Evolutionary_Algorithm_with_Application_to_the_Detection_of_Distributed_Computer_Network_Intrusions
