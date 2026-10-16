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


## Resolução de marx por triangulação de fontes

A listagem oficial de hosts internos do MIT em 1999 não inclui o nome marx,
embora a lista oficial de ataques o inclua como destino. **Não inventamos uma
associação a partir dessa listagem incompleta.** Investigações publicadas
sobre o mesmo benchmark, porém, identificam marx.eyrie.af.mil como
**172.16.114.50**:

- Estudo sobre detecção de ataques web e análise HTTP no DARPA 1999,
  Computer Networks 45 (2004), pp. 175–193:
  https://citeseerx.ist.psu.edu/document?doi=09d599a09ed0010b650c7b078c52d6780b7ab794&repid=rep1&type=pdf
- Detection of Web-based Attacks through Markovian Protocol Parsing:
  https://citeseerx.ist.psu.edu/document?doi=0ea94147c57398653a5797414986963338248227&repid=rep1&type=pdf
- Estudo Variable Shaped Detector também utiliza o endereço
  172.16.114.50 para marx na semana de ataques:
  https://citeseerx.ist.psu.edu/document?doi=ca587f68e4f7a10f4322f449da44ee535cc96c22&repid=rep1&type=pdf

Na primeira extração de metadados, 172.16.114.50 surgiu como destino mais
frequente nas três janelas referentes aos ataques IDs 17, 24 e 36. Isso
fornece **corroboração empírica** da associação sugerida por pesquisas
anteriores. Seu estatuto deve ser registrado como
*host mapeado por literatura secundária e dados observados*, e NÃO como
mapeamento diretamente listado pelo MIT.

A associação de endereço reforça a análise, mas **não resolve o problema de
atribuir cada pacote a uma sessão maliciosa específica**. Para isso
são necessárias informações adicionais de autoria, duração ou rotulação
por fluxo/pacote. Essa distinção deve permanecer explícita no relatório final.

## Controle de integridade das flags TCP

A primeira execução de metadados com campos booleanos individuais do TShark
retornou zero flags TCP apesar de haver dezenas de milhares de segmentos TCP.
Esta rodada NÃO fornece resultados válidos de flags e não deve ser usada no
relatório experimental.

O extrator foi corrigido para ler o campo numérico tcp.flags e usar as
máscaras SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01. Uma asserção impede que
a execução publique resultados com todas as flags zeradas. Apenas os
resultados da execução corrigida, quando validados, devem ser empregados.
