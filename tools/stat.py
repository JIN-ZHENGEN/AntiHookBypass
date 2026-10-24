import re,subprocess,json,sys
out=subprocess.run(['su','-c','cat /data/local/tmp/cur.log'],capture_output=True,text=True).stdout
def parse(tag):
    parts=[]
    for l in out.splitlines():
        m=re.search(tag+r' \[\d+\] (.*)$', l)
        if m: parts.append(m.group(1))
    s=''.join(parts)
    if '[' not in s: return None
    s=s[s.index('['):]
    try: return json.loads(s)
    except Exception: return None
data=parse('VERDICT-AFTER') or parse('VERDICT')
if data is None:
    print("NO_SCAN"); sys.exit()
bad=[(it['id'],it['status']) for it in data if it['status']!='SAFE']
print("6/6 ALL SAFE" if not bad else "FAIL "+str(bad))
