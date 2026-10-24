#!/usr/bin/env python3
"""ORDER SOC v2.3: weekly executive IOC report from archived daily summaries.
No firewall actions, no live customer traffic data, no writes to GitHub.
"""
from __future__ import annotations
import argparse
import base64
import csv
import html
import json
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from string import Template
from zoneinfo import ZoneInfo

TZ = ZoneInfo('America/Santiago')
TYPES = ('ip', 'domain', 'sha256')
LABEL = {'ip': 'Direcciones IPv4', 'domain': 'Dominios', 'sha256': 'Hashes SHA256'}


def load_json(path):
    with Path(path).open(encoding='utf-8') as fd:
        return json.load(fd)


def week_dates(as_of):
    """Always the previous *completed* Monday–Sunday period."""
    this_monday = as_of - timedelta(days=as_of.weekday())
    start = this_monday - timedelta(days=7)
    return start, start + timedelta(days=6)


def build_data(daily_root, as_of=None):
    as_of = as_of or datetime.now(TZ).date()
    start, end = week_dates(as_of)
    root = Path(daily_root)
    days, missing, warnings = [], [], []
    for i in range(7):
        day = start + timedelta(days=i)
        path = root / day.isoformat() / 'summary.json'
        if not path.is_file():
            missing.append(day.isoformat())
            days.append({'date': day.isoformat(), 'available': False, 'added': None, 'removed': None,
                         'current': None, 'by_type': {typ: None for typ in TYPES}})
            continue
        doc = load_json(path)
        if doc.get('date_local') != day.isoformat() or doc.get('schema_version') != 1:
            raise ValueError(f'Archivo diario inconsistente: {path}')
        if doc.get('mode') not in ('DELTA', 'BASELINE', 'ALREADY_REPORTED'):
            raise ValueError(f'Modo inesperado en {path}')
        added = int(doc['count_added']) if doc['mode'] == 'DELTA' else None
        removed = int(doc['count_removed']) if doc['mode'] == 'DELTA' else None
        current = int(doc['count_current'])
        if min(x for x in (current, doc['count_added'], doc['count_removed'])) < 0:
            raise ValueError(f'Valores negativos en {path}')
        if doc['mode'] != 'DELTA':
            warnings.append(f'{day.isoformat()} es {doc["mode"]}; no se computa como altas/bajas.')
        days.append({'date': day.isoformat(), 'available': True, 'mode': doc['mode'],
                     'added': added, 'removed': removed, 'current': current,
                     'by_type': {k: int(doc.get('current_by_type', {}).get(k, 0)) for k in TYPES}})
    deltas = [d for d in days if d['available'] and d['added'] is not None]
    last_available = next((d for d in reversed(days) if d['available']), None)
    complete = len(deltas) == 7
    if missing:
        warnings.append('Días sin reporte archivado: ' + ', '.join(missing))
    if not complete:
        warnings.append('Cobertura parcial: las altas y bajas son sumas únicamente de días con modo DELTA.')
    # Report content MUST NEVER imply a FortiGate block from candidate feed history.
    return {
        'schema_version': 1, 'report_kind': 'ioc_weekly_executive',
        'period_start': start.isoformat(), 'period_end': end.isoformat(),
        'generated_at_local': datetime.now(TZ).isoformat(),
        'coverage_days': len(deltas), 'available_days': sum(d['available'] for d in days),
        'expected_days': 7, 'complete': complete, 'missing_days': missing,
        'added_observed': sum(d['added'] for d in deltas),
        'removed_observed': sum(d['removed'] for d in deltas),
        'last_observed_date': last_available['date'] if last_available else None,
        'current_observed': last_available['current'] if last_available else None,
        'current_by_type': last_available['by_type'] if last_available else None,
        'days': days, 'warnings': warnings,
        'client_impact_verified': False, 'firewall_blocks_verified': False,
        'data_scope': 'Inteligencia global ORDER SOC, NO telemetría de un cliente',
    }


def svg_data_uri(svg_path):
    p = Path(svg_path)
    mime = 'image/svg+xml' if p.suffix.lower() == '.svg' else 'image/png' if p.suffix.lower() == '.png' else None
    if not mime:
        raise ValueError('El logotipo debe ser SVG o PNG')
    if p.stat().st_size > 1_500_000:
        raise ValueError('Logotipo supera 1.5 MB')
    return 'data:' + mime + ';base64,' + base64.b64encode(p.read_bytes()).decode('ascii')


def render(data, config, template_path, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if data.get('client_impact_verified') or data.get('firewall_blocks_verified'):
        raise ValueError('No se admiten afirmaciones de impacto/bloqueo no corroboradas')
    logo_path = Path(config.get('logo_path', ''))
    logo = svg_data_uri(logo_path) if config.get('logo_path') and logo_path.is_file() else ''
    if not logo:
        raise ValueError('Falta logo_path local SVG/PNG válido. No generar informe sin identidad visual.')
    e = lambda v: html.escape(str(v), quote=True)
    has_data = data['current_observed'] is not None
    def fmt(x): return f'{x:,}'.replace(',', '.') if x is not None else 'N/D'
    daily_rows = []
    for d in data['days']:
        daily_rows.append('<tr>' + ''.join('<td>' + e(col) + '</td>' for col in (
            d['date'], fmt(d['current']), fmt(d['added']), fmt(d['removed']),
            'DELTA' if d.get('mode') == 'DELTA' else 'Línea base' if d.get('mode') == 'BASELINE' else 'Sin datos'
        )) + '</tr>')
    type_rows = []
    for typ in TYPES:
        val = data['current_by_type'][typ] if has_data else None
        type_rows.append(f'<tr><td>{e(LABEL[typ])}</td><td>{fmt(val)}</td></tr>')
    max_value = max((d['added'] for d in data['days'] if d['added'] is not None), default=0)
    graph = []
    for d in data['days']:
        height = max(3, round(100 * d['added'] / max_value)) if max_value and d['added'] is not None else 3
        graph.append('<div class="chart-day"><div class="bar-wrap"><div class="bar" style="height:' + str(height) + '%"></div></div>'
                     + f'<span>{e(d["date"][5:])}</span><b>{fmt(d["added"])}</b></div>')
    warnings = ''.join('<li>' + e(x) + '</li>' for x in data['warnings'])
    if not warnings: warnings = '<li>Sin advertencias sobre cobertura de informes diarios.</li>'
    scope = 'COMPARTIBLE CON CLIENTE · INTELIGENCIA GLOBAL, SIN TELEMETRÍA DE CLIENTE'
    mapping = {
        'brand_name': e(config.get('brand_name', 'ORDER TECHNOLOGY')),
        'client_name': e(config.get('client_name', 'Informe general de inteligencia')),
        'report_classification': e(config.get('classification', 'Uso externo autorizado')),
        'period': e(data['period_start'] + ' a ' + data['period_end']),
        'generated': e(data['generated_at_local'][:16].replace('T',' ')),
        'state': 'COBERTURA COMPLETA' if data['complete'] else f'COBERTURA PARCIAL {data["coverage_days"]}/7',
        'number_current': fmt(data['current_observed']),
        'number_added': fmt(data['added_observed']) if data['coverage_days'] else 'N/D',
        'number_removed': fmt(data['removed_observed']) if data['coverage_days'] else 'N/D',
        'coverage': f'{data["coverage_days"]} de 7 días con diferencias válidas',
        'last_day': e(data['last_observed_date'] or 'Sin día registrado'),
        'logo_data_uri': logo,
        'type_rows': ''.join(type_rows), 'daily_rows': ''.join(daily_rows),
        'graph': ''.join(graph), 'warnings': warnings,
        'scope': scope,
        'notes': e(config.get('executive_note', 'Actividad de inteligencia consolidada por ORDER SOC. No representa tráfico ni incidentes verificados del cliente.')),
        'footer': e(config.get('footer', 'ORDER SOC | Inteligencia de amenazas y ciberseguridad')),
    }
    template = Template(Path(template_path).read_text(encoding='utf-8'))
    html_text = template.substitute(mapping)
    (out / 'weekly-client-report.html').write_text(html_text, encoding='utf-8')
    (out / 'weekly-summary.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    text = [f'# ORDER SOC | Semana {data["period_start"]} – {data["period_end"]}', '',
            f'**Cobertura:** {data["coverage_days"]}/7 días DELTA',
            f'**IOC al último día registrado:** {fmt(data["current_observed"])}',
            f'**Altas observadas:** {fmt(data["added_observed"]) if data["coverage_days"] else "N/D"}',
            f'**Bajas observadas:** {fmt(data["removed_observed"]) if data["coverage_days"] else "N/D"}', '',
            'Las altas/bajas reflejan el historial IOC y NO cambios en las políticas FortiGate.',
            'No existe integración de telemetría cliente/FAZ en esta versión.', '',
            '## Advertencias', *(f'- {x}' for x in data['warnings']), '']
    (out / 'weekly-summary.md').write_text('\n'.join(text), encoding='utf-8')
    return out / 'weekly-client-report.html'


def main():
    p = argparse.ArgumentParser(description='ORDER SOC weekly executive report — REVIEW ONLY')
    p.add_argument('--daily-root', default='build/ioc-state/reports/daily')
    p.add_argument('--client-config', default='config/branding.json')
    p.add_argument('--template', default='templates/weekly_report_client.html')
    p.add_argument('--out', default='build/weekly-report')
    p.add_argument('--as-of', help='YYYY-MM-DD; calcula semana anterior concluida')
    a = p.parse_args()
    current = date.fromisoformat(a.as_of) if a.as_of else None
    report = build_data(a.daily_root, current)
    report_path = render(report, load_json(a.client_config), a.template, a.out)
    print(f'REPORT_READY={report_path}; coverage={report["coverage_days"]}/7; complete={report["complete"]}')


if __name__ == '__main__':
    main()
