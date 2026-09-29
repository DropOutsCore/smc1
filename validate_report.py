import json
with open('reports_out/smtp_tls10_deprecated_report.json') as f:
    r = json.load(f)
print('report_id:', r['report_id'][:16], '...')
print('source_pcap_sha256:', r['source_pcap_sha256'][:32], '...')
print('hosts:', len(r['hosts']))
for h in r['hosts']:
    host = h['host']
    grade = h['posture_grade']
    score = h['posture_score']
    print(f'  host={host} grade={grade} score={score}')
    for s in h['sessions']:
        tls = s['tls_version']
        cs = s['cipher_suite']
        pfs = s['pfs']
        print(f'    session tls={tls} cipher={cs} pfs={pfs}')
        for finding in s['findings']:
            fid = finding['id']
            sev = finding['severity'].upper()
            pkt = finding['evidence_ref']['packet_number']
            print(f'      [{sev:8}] {fid:30s} pkt={pkt}')
sha = r['custody'].get('report_sha256', 'N/A')
print('report_sha256:', sha[:32] if sha else 'N/A', '...')
print('Schema OK - all fields present')
