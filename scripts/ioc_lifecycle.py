#!/usr/bin/env python3
"""ORDER SOC v2.3: local, auditable IOC decision register.

NEVER writes to feeds or FortiGate. Store the database in a protected private
SOC location; default build/ is intended as an untracked local workspace.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

DOMAIN = re.compile(r'^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')
SHA = re.compile(r'^[a-fA-F0-9]{64}$')
SHARED = ('workers.dev', 'pages.dev', 'github.io', 'cloudfront.net', 'vercel.app',
          'amazonaws.com', 'azurewebsites.net', 'netlify.app', 'googleusercontent.com')
FEED_PATHS = {
    'ip': ('ips.txt', 'feeds/ips-critical.txt', 'feeds/ips-suspicious.txt'),
    'domain': ('feeds/domains-malicious.txt',),
    'sha256': ('hash-256.txt', 'feeds/hashes-sha256.txt'),
}


def normalize(kind, raw):
    value = raw.strip()
    if kind == 'ip':
        try:
            obj = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError('IPv4 inválida') from exc
        if obj.version != 4 or not obj.is_global:
            raise ValueError('Solo IPv4 globales; no incluir IP de laboratorio/privadas')
        return str(obj)
    if kind == 'domain':
        try:
            value = value.rstrip('.').encode('idna').decode('ascii').lower()
        except (UnicodeError, ValueError) as exc:
            raise ValueError('Dominio inválido') from exc
        if not DOMAIN.fullmatch(value) or value.endswith('.onion'):
            raise ValueError('Dominio inválido o .onion no soportado')
        return value
    if kind == 'sha256':
        if not SHA.fullmatch(value):
            raise ValueError('SHA256 debe tener 64 caracteres hexadecimales')
        return value.lower()
    raise ValueError('Tipo no soportado (ip, domain, sha256)')


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def load_state(path):
    path = Path(path)
    if not path.exists():
        return {'schema_version': 1, 'decisions': {}, 'events': []}
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != 1 or not isinstance(data.get('decisions'), dict) or not isinstance(data.get('events'), list):
        raise ValueError('Registro de decisiones inválido; no sobrescribir')
    return data


def save_state(path, state):
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix='.soc-decisions-', suffix='.json', dir=str(dest.parent), text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write('\n')
        os.replace(temp_name, dest)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def event(state, key, action, actor, ticket, detail=None):
    state['events'].append({'at_utc': utcnow(), 'key': key, 'action': action,
                            'actor': actor, 'ticket': ticket, 'detail': detail or {}})


def find_presence(kind, value, state, root='.', history=None):
    key = f'{kind}|{value}'
    paths = []
    root_path = Path(root)
    # This is an exact-line scan, not a CIDR/range matcher or proof of application.
    for filename in FEED_PATHS[kind]:
        f = root_path / filename
        if f.is_file():
            with f.open(encoding='utf-8', errors='replace') as handle:
                if any(line.strip() == value for line in handle):
                    paths.append(filename)
    hist = None
    if history and Path(history).is_file():
        doc = json.loads(Path(history).read_text(encoding='utf-8'))
        hist = (doc.get('indicators') or {}).get(key)
    decision = state['decisions'].get(key)
    return {'ioc': value, 'type': kind, 'found_in_static_feeds_exact': paths,
            'found_in_history': hist is not None, 'history_status': hist.get('status') if hist else None,
            'decision_status': decision.get('status') if decision else None,
            'decision': decision,
            'caution': 'Coincidencia exacta local. No verifica reputación externa ni confirma bloqueo en FortiGate.'}


def process(args, state):
    kind, value = args.type, normalize(args.type, args.value)
    key = f'{kind}|{value}'
    existing = state['decisions'].get(key)
    if args.command == 'check':
        return find_presence(kind, value, state, args.root, args.history), False
    if args.command == 'propose':
        if existing and existing['status'] not in ('rejected', 'revoked', 'expired'):
            raise ValueError(f'Ya existe un registro SOC ({existing["status"]}); utilizar check')
        if not all((args.ticket.strip(), args.actor.strip(), args.source.strip(), args.reason.strip())):
            raise ValueError('ticket, analyst, source y reason son obligatorios')
        state['decisions'][key] = {
            'type': kind, 'value': value, 'status': 'candidate',
            'proposer': args.actor, 'ticket': args.ticket, 'source': args.source,
            'reason': args.reason, 'evidence_url': args.evidence_url or None,
            'created_at_utc': utcnow(), 'proposed_scope': 'indicator',
            'verified_by': None, 'approved_by': None, 'decision': None,
            'expires_on': None,
            'risk_flags': (['shared_hosting_exact_match_only'] if kind == 'domain' and
                           any(value == x or value.endswith('.' + x) for x in SHARED) else
                           ['ip_wide_block_requires_approval'] if kind == 'ip' else []),
        }
        event(state, key, 'propose', args.actor, args.ticket, {'source': args.source})
    elif args.command == 'verify':
        if not existing or existing['status'] != 'candidate':
            raise ValueError('Se requiere una propuesta en estado candidate')
        if not args.actor or args.actor == existing['proposer']:
            raise ValueError('Verificador distinto del proponente (control de 2 personas)')
        if not args.evidence_url and not existing.get('evidence_url'):
            raise ValueError('Se requiere referencia de evidencia verificable')
        if args.verdict == 'confirmed':
            existing.update(status='verified', verified_by=args.actor,
                            evidence_url=args.evidence_url or existing['evidence_url'],
                            verified_at_utc=utcnow(), verification_notes=args.notes)
        else:
            existing.update(status='rejected', verified_by=args.actor,
                            verified_at_utc=utcnow(), verification_notes=args.notes)
        event(state, key, 'verify_' + args.verdict, args.actor, existing['ticket'])
    elif args.command == 'approve':
        if not existing or existing['status'] != 'verified':
            raise ValueError('IOC debe estar verified antes de aprobar')
        if not args.actor or args.actor in (existing['proposer'], existing['verified_by']):
            raise ValueError('Aprobador distinto del proponente y del verificador')
        if not args.ticket or args.ticket != existing['ticket']:
            raise ValueError('Ticket de la aprobación debe coincidir')
        expires = date.fromisoformat(args.expires_on)
        if expires <= date.today():
            raise ValueError('Fecha de caducidad debe ser futura')
        if args.decision == 'block':
            if not args.ack_risk:
                raise ValueError('Bloqueo requiere --ack-risk (impacto/falsos positivos revisados)')
            if kind == 'ip' and args.scope != 'ip_exact':
                raise ValueError('Bloqueo de IP requiere alcance ip_exact confirmado (no ip:puerto)')
            if kind == 'domain' and args.scope != 'domain_exact':
                raise ValueError('Bloqueo dominio requiere dominio exacto')
            if kind == 'sha256' and args.scope != 'file_sha256':
                raise ValueError('Hash solo alcance file_sha256')
        existing.update(status='approved_monitoring' if args.decision == 'monitor' else 'approved_blocking',
                        approved_by=args.actor, approved_at_utc=utcnow(), decision=args.decision,
                        scope=args.scope, expires_on=args.expires_on,
                        deployment_state='NOT_DEPLOYED',
                        note='La aprobación NO publica feed ni aplica bloqueo en dispositivos')
        event(state, key, 'approve_' + args.decision, args.actor, args.ticket, {'scope': args.scope})
    elif args.command == 'revoke':
        if not existing or existing['status'] not in ('approved_monitoring', 'approved_blocking', 'verified'):
            raise ValueError('No existe una decisión activa que revocar')
        if not args.reason or not args.ticket or not args.actor:
            raise ValueError('Revocación requiere actor, ticket y motivo')
        existing.update(status='revoked', revoked_at_utc=utcnow(), revoked_by=args.actor,
                        revoked_reason=args.reason, deployment_state='CHECK_EXTERNAL_DEPLOYMENT')
        event(state, key, 'revoke', args.actor, args.ticket, {'reason': args.reason})
    else:
        raise ValueError('Acción no soportada')
    return {'key': key, 'status': state['decisions'][key]['status'],
            'production_changed': False, 'manual_followup_required': True}, True


def parse_args(argv=None):
    p = argparse.ArgumentParser(description='Gestión local IOC ORDER SOC — sin cambios en producción')
    p.add_argument('--state', default='build/soc-ioc-decisions.json')
    p.add_argument('--root', default='.')
    p.add_argument('--history', default=None)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('check', 'propose', 'verify', 'approve', 'revoke'):
        s = sub.add_parser(name)
        s.add_argument('--type', choices=['ip', 'domain', 'sha256'], required=True)
        s.add_argument('--value', required=True)
        if name != 'check':
            s.add_argument('--actor', required=True)
            s.add_argument('--ticket', required=name in ('propose', 'approve', 'revoke'))
        if name in ('propose', 'revoke'):
            s.add_argument('--reason', required=True)
        if name == 'propose':
            s.add_argument('--source', required=True)
            s.add_argument('--evidence-url')
        if name == 'verify':
            s.add_argument('--verdict', choices=['confirmed', 'rejected'], required=True)
            s.add_argument('--evidence-url')
            s.add_argument('--notes', default='')
        if name == 'approve':
            s.add_argument('--decision', choices=['monitor', 'block'], required=True)
            s.add_argument('--scope', choices=['indicator', 'ip_exact', 'domain_exact', 'file_sha256'], default='indicator')
            s.add_argument('--expires-on', required=True)
            s.add_argument('--ack-risk', action='store_true')
    return p.parse_args(argv)


def main():
    p = parse_args()
    state = load_state(p.state)
    try:
        result, changed = process(p, state)
    except ValueError as exc:
        raise SystemExit('VALIDATION_ERROR: ' + str(exc)) from exc
    if changed:
        save_state(p.state, state)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
