import json, collections
H = json.load(open('/tmp/handlers.json'))
KEY = {0xc8,0xd4,0xd8}
IPF = {0x6c,0x70,0x74,0x78,0x84,0x88,0x8c,0x90}
WORK = {0x04,0x14,0x1c,0x20,0x2c,0x34,0x3c,0x40,0x54,0x98,0xb0,0xb4}
def sig(h):
    r = set(int(x,16) for x in h['reads']); w = set(int(x,16) for x in h['writes'])
    tags = []
    if r & KEY and w & KEY: tags.append('key-evolve')
    if r & KEY and not w & KEY: tags.append('key-read')
    if 0x6c in r: tags.append('ip-read')
    if 0x6c in w: tags.append('ip-write')
    if r & WORK and w & WORK: tags.append('vreg-io')
    elif r & WORK: tags.append('vreg-read')
    if 0x38 in r: tags.append('table-ref')
    if 'rdtsc' in h['feats']: tags.append('RDTSC')
    if 'call' in h['feats']: tags.append('CALL')
    if 'eflags' in h['feats']: tags.append('eflags')
    if 'shift' in h['feats']: tags.append('shift')
    if 'mul' in h['feats']: tags.append('mul')
    return tuple(tags) or ('plain',)
cl = collections.Counter(sig(h) for h in H)
print("=== handler archetypes (tag-combo : count) ===")
for t,c in cl.most_common(25): print(f"  {c:4}  {', '.join(t)}")
# notable handlers
print("\n=== rdtsc handler ===")
for h in H:
    if 'rdtsc' in h['feats']:
        print(f"  VA {h['va']:#x}, {h['n']} insns, reads={[x for x in h['reads']][:10]}, feats={h['feats']}")
print("\n=== calling handlers (4) ===")
for h in H:
    if 'call' in h['feats']:
        print(f"  VA {h['va']:#x}, {h['n']} insns, mn={ {k:v for k,v in h['mn'].items() if v>=1} }")
# size stats
sizes = sorted(h['n'] for h in H)
print(f"\nhandler lengths (insns until first jmp/ret or 120 cap): min={sizes[0]} p25={sizes[len(sizes)//4]} median={sizes[len(sizes)//2]} p75={sizes[3*len(sizes)//4]} max={sizes[-1]}")
# how many handlers read the dispatch table 0x38
print(f"handlers referencing ctx+0x38 (dispatch table): {sum(1 for h in H if '0x38' in h['reads'])}")
# handlers with no ctx access at all?
noc = [h for h in H if not h['reads'] and not h['writes']]
print(f"handlers with NO ctx access: {len(noc)}", [hex(h['va']) for h in noc[:5]])
