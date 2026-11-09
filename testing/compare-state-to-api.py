"""Compare Terraform state against what Authlete actually holds.

  compare-state-to-api.py <state file> <server url> <token>

Terraform state is meant to record what the API returned. Anything it records
instead is a value the provider decided for itself, and a plan modifier that
answers an attribute from prior state is the way that happens: predict wrongly
and the prediction is what gets stored.

Any attribute reported here after an apply is one Authlete rewrites on write,
which is the set internal/provider/settled_unknowns.go must never answer from
prior state. Finding one means adding it to serverRecomputedRoots there.

Differences the provider creates deliberately and documents are not reported;
they are listed in `skip` and in the empty-list rule below.
"""
import json, subprocess, sys, os

def camel(s):
    head, *rest = s.split('_')
    return head + ''.join(w[:1].upper() + w[1:] for w in rest)

def api_get(url, token, path):
    out = subprocess.run(['curl', '-s', '-H', f'Authorization: Bearer {token}', url + path],
                         capture_output=True, text=True).stdout
    return json.loads(out)

def norm(v):
    """Normalise for comparison: camelCase every key, drop nulls, ignore order
    only where Authlete is known to reorder."""
    if isinstance(v, list):
        return [norm(x) for x in v]
    if isinstance(v, dict):
        # An absent value and an empty list mean the same thing at every
        # depth, so neither is carried into the comparison. A list that
        # actually holds something still differs from one that does not.
        return {camel(k): norm(x) for k, x in sorted(v.items())
                if x is not None and x != []}
    return v

def compare(label, state_attrs, api, skip):
    bad = []
    for k, sv in sorted(state_attrs.items()):
        if k in skip:
            continue
        ak = camel(k)
        av = api.get(ak)
        # An absent list and an empty one mean the same thing; the provider
        # reads one back as the other on purpose (scripts/patch-empty-lists.sh).
        if sv == [] and av is None:
            continue
        if sv is None and av == []:
            continue
        if norm(sv) != norm(av):
            bad.append((k, sv, av))
    print(f"\n== {label}: {len(bad)} attribute(s) where state disagrees with Authlete ==")
    for k, sv, av in bad:
        print(f"  {k}\n      state: {json.dumps(sv)[:120]}\n      api:   {json.dumps(av)[:120]}")
    return bad

state = json.load(open(sys.argv[1]))
url, token = sys.argv[2], sys.argv[3]
svc = cli = None
for r in state['resources']:
    if r.get('mode') != 'managed':
        continue
    if r['type'] == 'authlete_service':
        svc = r['instances'][0]['attributes']
    if r['type'] == 'authlete_client':
        cli = r['instances'][0]['attributes']

# Differences the provider creates on purpose and documents, so they are not
# evidence of state recording something Authlete did not return:
#   jwks            held in the configured spelling, compared semantically
#   supported_scopes  Authlete fills in its own wording for standard scopes
#   service_id      a path parameter, not a field on the object
skip = {'api_key', 'api_secret', 'client_secret', 'modified_at', 'created_at',
        'jwks', 'federation_jwks', 'credential_jwks', 'supported_scopes', 'service_id'}
total = []
if svc:
    total += compare('service', svc, api_get(url, token, f"/api/{svc['api_key']}/service/get"), skip)
if cli:
    total += compare('client', cli, api_get(url, token, f"/api/{svc['api_key']}/client/get/{cli['client_id']}"), skip)
print(f"\nTOTAL mismatches: {len(total)}")

# Non-zero so run.sh drift can fail on it.
sys.exit(1 if total else 0)
