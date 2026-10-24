import re,subprocess,json,sys
out=subprocess.run(['su','-c','cat /data/local/tmp/cur.log'],capture_output=True,text=True).stdout
# 行形如: VERDICT com.x.NativeLib.scan [0] [...]  /  VERDICT-AFTER [0] [...]
pat=re.compile(r'(VERDICT(?:-AFTER)?)(?: \S+)? \[(\d+)\] (.*)$')
buf={'VERDICT':[], 'VERDICT-AFTER':[]}
for l in out.splitlines():
    m=pat.search(l)
    if m: buf[m.group(1)].append((int(m.group(2)), m.group(3)))
def build(tag):
    parts=sorted(buf[tag])
    s=''.join(p[1] for p in parts)
    if '[' not in s: return None
    try: return json.loads(s[s.index('['):])
    except Exception as e: return None
b=build('VERDICT'); a=build('VERDICT-AFTER')
if not b: print("无改写前数据"); sys.exit()
am={x['id']:x for x in (a or [])}
for x in b:
    y=am.get(x['id'],x)
    same=x['status']==y['status']
    who='内存层(本就干净)' if (same and x['status']=='SAFE') else ('结果层归一化' if not same else '未修')
    print(f"{x['id']:26} {x['status']:6} -> {y['status']:6}  {who}")
