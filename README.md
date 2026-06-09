# Hybrid IDS — Sistema de detección de intrusiones (reglas + anomalías)

IDS híbrido en Python que analiza **logs y flujos de red** combinando dos
métodos de detección complementarios:

- **Detección por firmas/reglas** (estilo Snort/Suricata): reglas declarativas
  en YAML, incluyendo reglas con estado por umbral y ventana temporal (fuerza
  bruta, escaneo).
- **Detección por anomalías** (estadística): perfila el comportamiento por IP de
  origen y marca desviaciones — escaneo de puertos, ratio de errores HTTP
  elevado y valores atípicos de volumen por z-score.
- **Correlación entre detectores**: detecta cadenas de ataque multi-etapa que
  ninguna alerta individual revela (p. ej. fuerza bruta SSH seguida de un login
  correcto = compromiso probable), elevando la gravedad y mapeándolas a
  técnicas **MITRE ATT&CK**.
- **Enriquecimiento de inteligencia de amenazas**: para cada IP de origen añade
  contexto (país, ASN, reputación, score de abuso, categorías) desde un feed
  local o desde la API de AbuseIPDB, y escala la gravedad de las alertas que
  apuntan a IPs maliciosas o sospechosas.

## Arquitectura

```
Fuentes (auth.log, access.log, flows/pcap)
        │
        ▼
   Parsers  ──►  Event normalizado
        │
        ├──►  Motor de reglas (firmas YAML + umbrales con ventana)
        └──►  Motor de anomalías (perfilado por IP + z-score)
                       │
                       ▼
                  Motor IDS  ──►  Alertas priorizadas (texto / JSON)
```

Un único modelo `Event` normaliza cada fuente, de modo que la lógica de
detección no depende del origen de los datos.

## Uso

```bash
# Análisis completo de las tres fuentes con las reglas por defecto
python -m ids.cli \
    --auth samples/auth.log \
    --web samples/access.log \
    --flows samples/flows.csv \
    --rules rules/default.yaml

# Con enriquecimiento de inteligencia de amenazas
python -m ids.cli --auth samples/auth.log --web samples/access.log \
    --flows samples/flows.csv --enrich
