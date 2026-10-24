#!/usr/bin/env python3
"""ORDER SOC v2.2: delta diario entre snapshots del historial SOC.

Solo lectura de ioc-history; genera reportes para revisión. NO aprueba bloqueos,
NO modifica feeds actuales y NO realiza cambios en FortiGate.
"""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

VALID_TYPES = {'ip', 'domain', 'sha256'}


def parse_time(value):
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def read_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def slim_history(doc, now):
    """Conjunto vigente de IOC; la presencia en este snapshot NO indica bloqueo."""
    if doc.get('schema_version') != 2 or not isinstance(doc.get('indicators'), dict):
        raise ValueError('Historial de origen inválido (schema_version=2 e indicators obligatorios)')
    # Evita reportar como actual una base cuyo recolector lleva más de 26 horas sin actualizar.
    last_update = parse_time(doc.get('updated_at'))
    if last_update is None or (now - last_update).total_seconds() > 26 * 3600:
        raise ValueError('El historial está desactualizado (>26 h) o no tiene updated_at válido')
    result = {}
    for key, item in doc['indicators'].items():
        if not isinstance(item, dict) or item.get('type') not in VALID_TYPES:
            continue
        typ, val = item['type'], item.get('value', '')
        if not isinstance(val, str) or not val or key != f'{typ}|{val}':
            continue
        if item.get('status') not in ('active', 'historical_within_ttl'):
            continue
        expires = parse_time(item.get('expires_at'))
        if expires is None or expires <= now:
            continue
        result[key] = {
            'type': typ,
            'value': val,
            'classification': str(item.get('classification') or 'review'),
            'max_confidence': int(item.get('max_confidence') or 0),
            'ports': sorted({int(p) for p in item.get('observed_ports', []) if str(p).isdigit() and 1 <= int(p) <= 65535}),
            'expires_at': expires.isoformat(),
        }
    return result


def compare(current_doc, previous_doc=None, now=None, local_tz='America/Santiago'):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    local_date = now.astimezone(ZoneInfo(local_tz)).date().isoformat()
    current = slim_history(current_doc, now)
    past = {}
    baseline_date = None
    mode = 'BASELINE'
    if previous_doc is not None:
        if previous_doc.get('schema_version') != 1 or not isinstance(previous_doc.get('indicators'), dict):
            raise ValueError('Snapshot anterior inválido; abortando para evitar diferencias falsas')
        past = previous_doc['indicators']
        baseline_date = previous_doc.get('date_local')
        if not isinstance(baseline_date, str) or baseline_date > local_date:
            raise ValueError('Fecha del snapshot anterior inválida o futura')
        mode = 'ALREADY_REPORTED' if baseline_date == local_date else 'DELTA'

    added_keys = sorted(set(current) - set(past)) if mode == 'DELTA' else []
    removed_keys = sorted(set(past) - set(current)) if mode == 'DELTA' else []
    adds = [current[k] for k in added_keys]
    removals = []
    for k in removed_keys:
        rec = past[k]
        exp = parse_time(rec.get('expires_at'))
        reason = 'TTL_expirado' if exp is not None and exp <= now else 'no_vigente_verificar'
        removals.append(dict(rec, motivo_salida=reason))

    def type_counts(records):
        c = Counter(r.get('type', 'unknown') for r in records)
        return {t: c.get(t, 0) for t in ('ip', 'domain', 'sha256')}

    if mode == 'ALREADY_REPORTED':
        # Nunca cambia el baseline del mismo día: la persistencia está protegida por GitHub Actions.
        current = past
    summary = {
        'schema_version': 1,
        'mode': mode,
        'date_local': local_date,
        'timezone': local_tz,
        'generated_at_utc': now.astimezone(timezone.utc).isoformat(),
        'source_last_update_utc': current_doc.get('updated_at'),
        'previous_snapshot_date': baseline_date,
        'snapshot_interval_hours': (round((now - parse_time(previous_doc['generated_at_utc'])).total_seconds() / 3600, 2)
                                    if mode == 'DELTA' and parse_time(previous_doc.get('generated_at_utc')) else None),
        'count_current': len(current),
        'current_by_type': type_counts(current.values()),
        'count_added': len(adds),
        'added_by_type': type_counts(adds),
        'count_removed': len(removals),
        'removed_by_type': type_counts(removals),
        'removed_due_ttl': sum(1 for r in removals if r['motivo_salida'] == 'TTL_expirado'),
        'approved_for_block': 0,
        'production_feeds_changed': False,
        'note': ('Primer snapshot: establece línea base; NO atribuir todas las entradas a altas del día.'
                 if mode == 'BASELINE' else
                 'Diferencias entre snapshots diarios, NO equivalen a bloqueos en FortiGate.'),
    }
    snapshot = {'schema_version': 1, 'date_local': local_date,
                'generated_at_utc': summary['generated_at_utc'], 'indicators': current}
    return summary, adds, removals, snapshot


def save_report(output, summary, added, removed, snapshot):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (output / 'snapshot.json').write_text(json.dumps(snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n', encoding='utf-8')
    def write_csv(fname, rows, removed_mode=False):
        cols = ['tipo', 'indicador', 'clasificacion', 'confianza_fuente', 'puertos', 'expira_utc']
        if removed_mode:
            cols.append('motivo_salida')
        with (output / fname).open('w', newline='', encoding='utf-8') as f:
            wr = csv.DictWriter(f, fieldnames=cols)
            wr.writeheader()
            for x in rows:
                d = dict(tipo=x['type'], indicador=x['value'], clasificacion=x.get('classification', ''),
                         confianza_fuente=x.get('max_confidence', ''),
                         puertos=';'.join(map(str, x.get('ports', []))), expira_utc=x.get('expires_at', ''))
                if removed_mode:
                    d['motivo_salida'] = x['motivo_salida']
                wr.writerow(d)
    write_csv('added.csv', added)
    write_csv('removed.csv', removed, True)
    s = summary
    md = [f"# ORDER SOC | Reporte diario IOC | {s['date_local']}", '',
          f"**Modalidad:** {s['mode']} — solo revisión, sin bloqueo automático", '',
          f"- Fecha de línea base previa: **{s['previous_snapshot_date'] or 'Ninguna (primera ejecución)'}**",
          f"- Última actualización del historial: **{s['source_last_update_utc']}**",
          f"- IOC vigentes en historial: **{s['count_current']}**",
          f"- Nuevos respecto del snapshot previo: **{s['count_added']}**",
          f"- Salidos del conjunto vigente: **{s['count_removed']}**",
          f"- Salidas compatibles con expiración TTL: **{s['removed_due_ttl']}**",
          f"- IOC aprobados para bloqueo: **0**", '',
          '| Tipo | Vigentes | Altas | Bajas |',
          '|---|---:|---:|---:|']
    labels = {'ip': 'IPv4', 'domain': 'Dominio', 'sha256': 'SHA256'}
    for typ in ('ip', 'domain', 'sha256'):
        md.append(f"| {labels[typ]} | {s['current_by_type'][typ]} | {s['added_by_type'][typ]} | {s['removed_by_type'][typ]} |")
    md += ['', f"> {s['note']}", '',
           'Los listados detallados están en `added.csv` y `removed.csv`.',
           'Las bajas significan que el IOC dejó el conjunto vigente del historial; **no** implican que haya sido retirado de un FortiGate.',
           'Los IOC nuevos no deben bloquearse sin revisión, aprobación y comprobación de posibles falsos positivos.', '']
    (output / 'daily-report.md').write_text('\n'.join(md), encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description='Reporte diario de diferencias del historial ORDER SOC')
    parser.add_argument('--current', required=True)
    parser.add_argument('--previous')
    parser.add_argument('--output', default='build/daily-report')
    parser.add_argument('--timezone', default='America/Santiago')
    args = parser.parse_args()
    current_doc = read_json(args.current)
    previous_doc = read_json(args.previous) if args.previous and Path(args.previous).exists() else None
    summary, adds, removals, snapshot = compare(current_doc, previous_doc, local_tz=args.timezone)
    save_report(args.output, summary, adds, removals, snapshot)
    print(json.dumps({k:summary[k] for k in ['mode','date_local','previous_snapshot_date','count_current','count_added','count_removed','removed_due_ttl','approved_for_block']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
