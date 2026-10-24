#!/usr/bin/env python3
"""ORDER SOC v2.1 - Audit candidates and build a REVIEW-ONLY SOC queue.

This script never modifies a FortiGate, a source feed, or a GitHub repository.
It checks that the previous stage did not inadvertently approve blocking.
"""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def analyze(validated, summary, outdir):
    if validated.get('schema_version') != 2 or not isinstance(validated.get('candidates'), list):
        raise ValueError('Entrada de IOC validada debe tener schema_version=2')
    if (summary.get('mode') != 'REVIEW_ONLY' or summary.get('applied_to_firewalls') is not False
            or summary.get('production_feeds_changed') is not False
            or summary.get('counts', {}).get('ips-critical.txt') != 0):
        raise ValueError('BLOQUEO DE SEGURIDAD: el pipeline dejo de operar en modo REVIEW_ONLY')
    candidates = validated['candidates']
    by_type, priorities, risk_flags, sources = Counter(), Counter(), Counter(), Counter()
    queue = []
    for c in candidates:
        typ = c.get('type', 'unknown')
        by_type[typ] += 1
        flags = set(c.get('risk_flags') or [])
        for flag in flags:
            risk_flags[flag] += 1
        evs = c.get('evidence') or []
        evidence_sources = sorted({str(e.get('source')) for e in evs if e.get('source')})
        independent_references = sorted({str(e.get('reference')) for e in evs if e.get('reference')})
        for source in evidence_sources:
            sources[source] += 1
        conf = int(c.get('max_confidence') or 0)
        c2 = any(str(e.get('threat_type') or '') == 'botnet_cc' for e in evs)
        shared = 'shared_hosting_domain_exact_match_only' in flags
        if conf >= 90 and c2 and independent_references and not shared:
            priority = 'P1-hunting'
        elif conf >= 75 or c2:
            priority = 'P2-revisar'
        else:
            priority = 'P3-contexto'
        priorities[priority] += 1
        scope = 'ip:port (no ampliar a IP)' if typ == 'ip' and c.get('ports') else (
            'dominio exacto, no dominio padre' if shared else 'indicador exacto')
        queue.append({
            'priority': priority, 'type': typ, 'indicator': c.get('value', ''),
            'confidence_source': conf, 'ports': ';'.join(str(p) for p in c.get('ports', [])),
            'scope': scope, 'risk_flags': ';'.join(sorted(flags)),
            'sources': ';'.join(evidence_sources),
            'external_references': ';'.join(independent_references),
            'approved_for_block': 'NO',
        })
    queue.sort(key=lambda x: ({'P1-hunting': 0, 'P2-revisar': 1, 'P3-contexto': 2}[x['priority']],
                              -x['confidence_source'], x['type'], x['indicator']))
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cols = ['priority', 'type', 'indicator', 'confidence_source', 'ports', 'scope',
            'risk_flags', 'sources', 'external_references', 'approved_for_block']
    with (outdir / 'soc-review-queue.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        writer.writerows(queue)
    result = {
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'mode': 'REVIEW_ONLY', 'automatic_blocking': False, 'total_candidates': len(candidates),
        'by_type': dict(sorted(by_type.items())), 'by_priority': dict(sorted(priorities.items())),
        'risk_flag_counts': dict(sorted(risk_flags.items())),
        'evidence_source_counts': dict(sorted(sources.items())),
        'feed_counts_for_review': summary['counts'],
        'history_active': summary.get('history_active'),
        'history_expired_removed': summary.get('history_expired_removed'),
        'url_observations_not_auto_blocked': summary.get('url_observations'),
        'caveats': [
            'P1 significa prioridad de investigacion, NO autorizacion de bloqueo.',
            'Confidence corresponde a la fuente, no a una corroboracion independiente.',
            'Los indicadores IP:puerto NO justifican bloqueo de IP en todos los puertos.',
            'Los dominios de hosting compartido requieren coincidencia exacta y revision.',
            'No redistribuir IOC externos en repositorios publicos sin validar licencias.',
        ],
    }
    (outdir / 'soc-quality.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    top = queue[:20]
    md = ['# ORDER SOC | Auditoria v2.1 (SOLO REVISION)', '',
          f"- IOC candidatos: **{len(candidates)}**", '- IOC autorizados para bloqueo: **0**',
          f"- IP candidatos: {by_type['ip']}", f"- Dominios candidatos: {by_type['domain']}",
          f"- SHA256 candidatos: {by_type['sha256']}",
          f"- Prioridad P1 hunting: {priorities['P1-hunting']}",
          f"- Prioridad P2: {priorities['P2-revisar']}",
          f"- Prioridad P3: {priorities['P3-contexto']}", '',
          '## Prioridad P1 y P2 (primeros 20)', '',
          '| Prioridad | Tipo | IOC | Confianza (fuente) | Puertos |',
          '|---|---|---|---:|---|']
    for item in top:
        md.append(f"| {item['priority']} | {item['type']} | `{item['indicator'].replace('|','')}` | {item['confidence_source']} | {item['ports']} |")
    md.extend(['', '## Control de cambios', '',
               'Este reporte no publica IOC en GitHub ni modifica firewalls, FortiManager o FortiAnalyzer.',
               'Toda accion de bloqueo requiere validacion humana y aprobacion segun el cliente.', ''])
    (outdir / 'soc-report.md').write_text('\n'.join(md), encoding='utf-8')
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--validated', default='build/validated_iocs.json')
    p.add_argument('--summary', default='build/staging/review/summary.json')
    p.add_argument('--output', default='build/staging/review')
    args = p.parse_args()
    v = json.loads(Path(args.validated).read_text(encoding='utf-8'))
    summary = json.loads(Path(args.summary).read_text(encoding='utf-8'))
    result = analyze(v, summary, args.output)
    print(json.dumps({k: result[k] for k in ('total_candidates', 'by_type', 'by_priority', 'mode')},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
