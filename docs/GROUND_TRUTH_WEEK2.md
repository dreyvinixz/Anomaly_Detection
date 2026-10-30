# Etapa 2 — Auditoria de ground truth, DARPA 1999 Week 2

## Evidências existentes e limitações

Os 43 registros oficiais da segunda semana de treinamento (8 a 12 de
março de 1999) contêm ID, data, horário de início, destino e tipo de
ataque. Eles NÃO definem as durações de cada sessão maliciosa.

Fontes:
- MIT Week 2: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html
- Inícios oficiais: https://archive.ll.mit.edu/ideval/docs/detections_1999.html
- Plano de avaliação, com EXEMPLOS de durações, não verdade exaustiva:
  https://archive.ll.mit.edu/ideval/docs/id99-eval-ll.html
- master_identifications.list (testes a partir de 29/03/1999; período incorreto):
  https://archive.ll.mit.edu/ideval/files/master_identifications.list

Não é válido emprestar as durações dos testes de 29/03 em diante, nem
deduzir que minutos sem início listado sejam benignos. A etapa anterior
examinou PCAPs reais e encontrou evidência protocolar para quatro IDs
(17, 24, 26 e 36), mas não estabeleceu seus limites temporais verdadeiros.

## Executar sobre dados reais já versionados

Instalar o projeto na raiz do repo:

    python -m pip install -e .
    darpa-anomaly ground-truth-week2

Ou:

    python -m anomaly_detection.ground_truth_week2

O comando gera em results/ground-truth-week2:

- minute_labels_tri_state.csv: todas as janelas capturadas, rótulo
  1 (ataque verificado), 0 (benigno verificado), vazio (desconhecido).
  Os inícios oficiais sem duração têm status official_onset_only.
- official_event_review_queue.csv: os 43 ataques e os respectivos
  horários EST/UTC, cobertura temporal da captura e marcação das
  quatro evidências de protocolo disponíveis para revisão prioritária.
- summary.json: cobertura dos rótulos e SHA256 das entradas.
- labels_complete_for_part_b.csv: exportado somente quando TODAS as
  janelas foram rotuladas com evidência verificada. Pode então ser
  usado com darpa-anomaly part-b --labels ARQUIVO.

Por padrão o registro de intervalos abaixo está vazio, pois ainda não
existe uma duração verificada para os 43 eventos. Assim, o primeiro
relatório é uma auditoria de cobertura, NÃO uma matriz de confusão.

## Registro de intervalos com proveniência

Edite data/ground_truth/week2_intervals_review.csv. Seu cabeçalho é:

    attack_id,label,start_utc,end_utc,review_status,evidence_url,reviewer,notes

Use label attack ou benign. Para ataque, o attack_id é um dos 43 IDs
oficiais. Para benign, deixe o ID vazio. Use horários ISO 8601 com
fuso, preferencialmente UTC, e fim EXCLUSIVO (ex.: 13:01:00Z).

- review_status candidate: hipótese de intervalo, com fonte ou nota,
  SEM efeito no rótulo binário;
- review_status verified: intervalo revisto, com URL HTTPS da evidência
  e responsável pela revisão. A validade científica da evidência
  continua dependendo da inspeção humana;
- ataque: 1 quando um segundo do intervalo verificado intercepta o minuto;
- benigno: 0 somente quando evidência revista cobre o minuto completo,
  sem início oficial nem hipótese/intervalo de ataque conflitante;
- em qualquer outro caso: rótulo desconhecido (campo vazio);
- conflitos geram erro; nada será rotulado benigno por exclusão.

Não adicionar durações ilustrativas do plano do MIT como se fossem
registros verificados. Ao analisar uma captura, documentar destino/IP,
assinatura de protocolo, sessão de origem, horários do primeiro/último
pacote e se o dado pertence efetivamente ao sensor INSIDE.

O rótulo por minuto indica ocorrência de ataque durante a janela,
não que todos os seus pacotes sejam maliciosos. Fluxos de baixo volume
e ataques sem manifestação no INSIDE podem exigir outros sensores.

## Plano de investigação

1. Encontrar registros de duração e segmentação da própria semana de
   TREINAMENTO, sem confundi-los com os testes (semanas 4 e 5).
2. Investigar primeiro IDs 17/24 (SATAN) e 26/36 (Neptune), cujos
   metadados de pacotes estão auditados na etapa anterior.
3. Registrar inicialmente intervalos candidate, verificar com pacotes
   e outra fonte independente; promover apenas o que for sustentado.
4. Encontrar intervalos comprovadamente benignos para calcular TN e FP
   no detector global, sem transformar automaticamente desconhecidos
   em negativos.
5. Quando houver cobertura completa, executar matriz de confusão e
   preparar os gráficos e relatório da Parte B.

A regra de aceitar fonte HTTPS e revisor não autentica a fonte sozinha.
O revisor deve avaliar a consistência com os 43 eventos e os PCAPs.
