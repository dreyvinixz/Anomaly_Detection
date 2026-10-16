# Etapa 5 — Verificação direcionada de pacotes (protocolo e destino)

## Objetivo

Inspecionar novamente os arquivos binários INSIDE originais da semana 2 do DARPA 1999,
correlacionar os quatro eventos mais próximos de alertas EWMA/MAD (IDs MIT
17, 24, 26 e 36) e fazer triagem dos 115 alertas do detector, incluindo os
106 que estavam fora da janela de ±5 minutos em torno dos ataques documentados.

Essa verificação acrescenta evidência de metadados de pacotes, mas
**não converte automaticamente alertas em verdadeiros ou falsos positivos**.

## Fontes e proveniência

- Capturas INSIDE: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html
- Tabela de inícios dos ataques: https://archive.ll.mit.edu/ideval/docs/detections_1999.html
- Inventário MIT dos hosts em 1999: https://archive.ll.mit.edu/ideval/docs/hosts_1999.html
- Relatório de proximidade de início: ../reports/week2-1999/stage3-4/README.md
- Relatório anterior com série e 115 alertas: ../reports/week2-1999/README.md

Ponto de atenção: o host pigeon.eyrie.af.mil é oficialmente 172.16.114.207.
O host marx.eyrie.af.mil aparece na lista de ataques, mas NÃO no inventário
de hosts internos de 1999 consultado. Por isso o código não atribui IP a marx,
nem trata o endereço mais frequente como o alvo com certeza.

## Procedimento

1. Baixar os cinco arquivos e validar gzip -t e hashes SHA-256 registrados
   na Etapa 2.
2. Analisar todos os quadros com TShark em streaming, extraindo apenas
   timestamp, tamanho, IP origem/destino, protocolo, porta de destino e flags
   TCP (SYN, ACK, RST, FIN), sem armazenar payload ou PCAP no Git.
3. Verificar que a contagem total de pacotes em cada captura continua
   idêntica ao snapshot da Etapa 2, e que a contagem de cada janela
   investigada é idêntica ao CSV original de 60 segundos.
4. Analisar as janelas dos 115 alertas.
5. Para os eventos 17/24/26/36, observar cinco minutos anteriores e seis
   janelas iniciando no minuto do ataque (janela de observação, não sua duração).
6. Agregar taxa de SYN sem ACK em PPS, diversidade de portas, distribuição
   de IPs e estatísticas de protocolos TCP/UDP/ICMP.
7. Categorizar fenótipo de tráfego para triagem humana, jamais como rótulo
   oficial benigno/malicioso.

## Limitações

- O MIT exige correspondência de destino e período real para creditar uma
  detecção. A tabela de treinamento fornece inícios, mas não rotula todas
  as sessões como benignas ou maliciosas.
- Mesmo quando um alvo oficial recebe SYN, isso não prova que aqueles
  pacotes sejam de um atacante específico.
- Fenótipos como SYN dominante, UDP dominante e tráfego misto são
  características observadas, não classes de intrusão.
- Os 106 alertas sem coincidência de início em ±5 min continuam como
  casos em investigação; os ataques podem prolongar-se para além do início.
- Não calcular precisão/recall/F1 sem determinar e auditar as sessões
  relevantes ou ter rótulos independentes de janela.

## Execução

No GitHub, o workflow packet-evidence.yml executa a extração integral em
runner Ubuntu e versiona somente os CSVs agregados, o JSON e dois gráficos.

No Linux, instalar TShark/gzip e o projeto; obter as capturas originais
com darpa-anomaly download e executar:

    python -m anomaly_detection.packet_evidence --pcaps data/raw

Os resultados são versionados em reports/week2-1999/stage5-packet-evidence
quando as verificações automatizadas são aprovadas.

Este estágio é uma auditoria empírica dos metadados do sensor, não um
classificador supervisionado por fluxo.
