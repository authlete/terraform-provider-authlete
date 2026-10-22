#!/usr/bin/env python3
"""Decide "this resource is gone" from the response body, not the status code.

Terraform answers "gone" by dropping the resource and planning a replacement,
so a wrong answer creates a second service or client and orphans the original,
which keeps running. The generated code answered it from the status alone: any
404 was gone, and Delete treated any 404 as success. An nginx error page, a
proxy, or a typo in server_url all return a 404, so pointing at a host that
does not serve Authlete made every resource plan for recreation.

Authlete does not use 404 consistently either:

    service read, server      403 with resultCode A458203, never 404
    service delete, IdP       404 with "Service is not found"
    client read and delete    404 with resultCode A001212 or A001214

So these patches replace the blanket 404 with a check on what the body says,
and add a second check on where it came from: a service id is unique to its
cluster, and a cluster that never had the service answers exactly as one that
deleted it.

The tests live in internal/provider/missing_service.go, which Speakeasy does
not generate and does not touch.

  patch-missing-service.py           apply
  patch-missing-service.py --check   verify, non-zero if any site is unpatched
"""
import sys

MARK = "// scripts/patch-missing-service.py"

# A data source cannot drop itself from state the way a resource can, because
# it was never in state. Asking for a service that does not exist is an error;
# what matters is that the error says so instead of printing a bare 403.
DATA_SOURCES = [
    "internal/provider/service_data_source.go",
    "internal/provider/client_data_source.go",
]

DS_BEFORE = '''	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
'''
DS_AFTER = '''	if serviceIsGone(res.RawResponse) { MARK
		summary, detail := serviceGoneMessage(fmt.Sprintf("%v", request.ServiceID))
		resp.Diagnostics.AddError(summary, detail)
		return
	}
	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
'''.replace("MARK", MARK)

# Everything from the status check through to the payload check. It is part of
# the Read patch so the anchor is unique to Read: Create ends with the same
# payload check, and anchoring on that alone patched Create instead. Create
# talks to the IdP, so the remembered host became login.authlete.com and every
# real deletion then read as a move to another host.
TAIL = '''	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
	if !(res.PAYLOAD != nil) {
'''

# Read, as Speakeasy generates it: any 404 is gone.
READ_PRISTINE = '''	if res.StatusCode == 404 {
		resp.State.RemoveResource(ctx)
		return
	}
''' + TAIL

# Read, as the first version of this script left it: the blanket 404 was still
# there, with the 403 check bolted on after.
READ_V1 = '''	if res.StatusCode == 404 {
		resp.State.RemoveResource(ctx)
		return
	}
	if serviceIsGone(res.RawResponse) { MARK
		resp.State.RemoveResource(ctx)
		return
	}
'''.replace("MARK", MARK) + TAIL

# Read, as the version before the no-record refusal left it.
READ_V2 = '''	if GONE(res.RawResponse) { MARK
		if was := movedHost(ctx, req.Private, res.RawResponse); was != "" {
			summary, detail := goneElsewhereMessage(was, responseHost(res.RawResponse))
			resp.Diagnostics.AddError(summary, detail)
			return
		}
		resp.State.RemoveResource(ctx)
		return
	}
'''.replace("MARK", MARK) + TAIL.replace(
    "\tif !(res.PAYLOAD != nil) {",
    "\trememberHost(ctx, resp.Private, res.RawResponse) " + MARK + "\n\tif !(res.PAYLOAD != nil) {")

READ_AFTER = '''	if GONE(res.RawResponse) { MARK
		if was := movedHost(ctx, req.Private, res.RawResponse); was != "" {
			summary, detail := goneElsewhereMessage(was, responseHost(res.RawResponse))
			resp.Diagnostics.AddError(summary, detail)
			return
		}
		if !hasRecord(ctx, req.Private) {
			summary, detail := noRecordMessage("PAYLOAD_LOWER", fmt.Sprintf("%v", request.IDFIELD))
			resp.Diagnostics.AddError(summary, detail)
			return
		}
		resp.State.RemoveResource(ctx)
		return
	}
'''.replace("MARK", MARK) + TAIL.replace(
    "\tif !(res.PAYLOAD != nil) {",
    "\trememberHost(ctx, resp.Private, res.RawResponse) " + MARK + "\n\tif !(res.PAYLOAD != nil) {")

# Create records where the resource lives, so a resource created and then
# looked for on another host is protected before any refresh has been saved.
# A plan does not save state, so with this on Read alone the review's own
# repro -- apply, change server_url, plan -- was still unguarded.
#
# The anchor is the whole Create block including the call, because Create and
# Read end with the same status and payload checks. Anchoring on that tail
# alone matched the already-patched Read and silently did nothing.
#
# The host recorded is the configured server_url, stamped on every response by
# the body-capturing transport, not the host that answered. Service Create is
# answered by the IdP, and recording that gave login.authlete.com.
CREATE = {'internal/provider/service_resource.go': ['\tres, err := r.client.Service.Create(ctx, *request, createOptions...)\n\tif err != nil {\n\t\tresp.Diagnostics.AddError("failure to invoke API", err.Error())\n\t\tif res != nil && res.RawResponse != nil {\n\t\t\tresp.Diagnostics.AddError("unexpected http request/response", debugResponse(res.RawResponse))\n\t\t}\n\t\treturn\n\t}\n\tif res == nil {\n\t\tresp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", res))\n\t\treturn\n\t}\n\tif res.StatusCode != 200 {\n\t\tresp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))\n\t\treturn\n\t}\n\tif !(res.Service != nil) {', '\tres, err := r.client.Service.Create(ctx, *request, createOptions...)\n\tif err != nil {\n\t\tresp.Diagnostics.AddError("failure to invoke API", err.Error())\n\t\tif res != nil && res.RawResponse != nil {\n\t\t\tresp.Diagnostics.AddError("unexpected http request/response", debugResponse(res.RawResponse))\n\t\t}\n\t\treturn\n\t}\n\tif res == nil {\n\t\tresp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", res))\n\t\treturn\n\t}\n\tif res.StatusCode != 200 {\n\t\tresp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))\n\t\treturn\n\t}\n\trememberHost(ctx, resp.Private, res.RawResponse) // scripts/patch-missing-service.py\n\tif !(res.Service != nil) {'], 'internal/provider/client_resource.go': ['\tres, err := r.client.ClientManagement.ClientCreateAPI(ctx, *request)\n\tif err != nil {\n\t\tresp.Diagnostics.AddError("failure to invoke API", err.Error())\n\t\tif res != nil && res.RawResponse != nil {\n\t\t\tresp.Diagnostics.AddError("unexpected http request/response", debugResponse(res.RawResponse))\n\t\t}\n\t\treturn\n\t}\n\tif res == nil {\n\t\tresp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", res))\n\t\treturn\n\t}\n\tswitch res.StatusCode {\n\tcase 200, 201:\n\t\tbreak\n\tdefault:\n\t\tresp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))\n\t\treturn\n\t}\n\tif !(res.Client != nil) {', '\tres, err := r.client.ClientManagement.ClientCreateAPI(ctx, *request)\n\tif err != nil {\n\t\tresp.Diagnostics.AddError("failure to invoke API", err.Error())\n\t\tif res != nil && res.RawResponse != nil {\n\t\t\tresp.Diagnostics.AddError("unexpected http request/response", debugResponse(res.RawResponse))\n\t\t}\n\t\treturn\n\t}\n\tif res == nil {\n\t\tresp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", res))\n\t\treturn\n\t}\n\tswitch res.StatusCode {\n\tcase 200, 201:\n\t\tbreak\n\tdefault:\n\t\tresp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))\n\t\treturn\n\t}\n\trememberHost(ctx, resp.Private, res.RawResponse) // scripts/patch-missing-service.py\n\tif !(res.Client != nil) {']}


DELETE_PRISTINE = '''	switch res.StatusCode {
	case 204, 404:
		break
'''
DELETE_V1 = '''	switch res.StatusCode {
	case 204, 404:
		break
	default:
		if serviceIsGone(res.RawResponse) { MARK
			break // already gone, so there is nothing to delete
		}
'''.replace("MARK", MARK)

# 204 is a delete. Anything else is only a success if the body says the object
# was already missing; a bare 404 from a proxy is not.
DELETE_AFTER = '''	switch res.StatusCode {
	case 204: MARK
		break
	default:
		if GONE(res.RawResponse) {
			if was := movedHost(ctx, req.Private, res.RawResponse); was != "" {
				summary, detail := goneElsewhereMessage(was, responseHost(res.RawResponse))
				resp.Diagnostics.AddError(summary, detail)
				return
			}
			CONFIRM
			break // already gone, so there is nothing to delete
		}
'''.replace("MARK", MARK)

# The identity server resolves a service by organization_id, api_server_id and
# idp_host, and answers "Service is not found" when any of them names another
# place. The record cannot catch that, because a read rewrites it from the same
# wrong configuration. The cluster can: it resolves a service id without
# reference to any of the three.
SERVICE_CONFIRM = '''if exists, known := serviceStillExists(ctx, r.client.ServiceManagement, request.ServiceID); exists || !known {
				summary, detail := serviceStillThereMessage(fmt.Sprintf("%v", request.ServiceID), locationOf(res.RawResponse))
				resp.Diagnostics.AddError(summary, detail)
				return
			}'''

# A client delete is answered by the cluster itself, so there is nothing
# further to confirm: the host check already covers the only place it could
# have come from.
# A client delete is answered by the cluster, so there is no second place to
# ask. But a wrong server_url answers for the service with A458203, which
# counts as the client being gone too, and with nothing recorded there is
# nothing to compare that against. Refuse rather than report a deletion that
# did not happen.
CLIENT_CONFIRM = '''if !hasRecord(ctx, req.Private) {
				summary, detail := noRecordMessage("client", fmt.Sprintf("%v", request.ClientID))
				resp.Diagnostics.AddError(summary, detail)
				return
			}'''

# The same, as the version before the host check left it, so reapplying over
# an already-patched tree is a no-op rather than a failure.
# Delete, as the version with the comment-only client confirmation left it.
DELETE_V4 = '''	switch res.StatusCode {
	case 204: MARK
		break
	default:
		if GONE(res.RawResponse) {
			if was := movedHost(ctx, req.Private, res.RawResponse); was != "" {
				summary, detail := goneElsewhereMessage(was, responseHost(res.RawResponse))
				resp.Diagnostics.AddError(summary, detail)
				return
			}
			// the cluster answered this directly, so there is nothing further to confirm
			break // already gone, so there is nothing to delete
		}
'''.replace("MARK", MARK)

DELETE_V3 = '''	switch res.StatusCode {
	case 204: MARK
		break
	default:
		if GONE(res.RawResponse) {
			if was := movedHost(ctx, req.Private, res.RawResponse); was != "" {
				summary, detail := goneElsewhereMessage(was, responseHost(res.RawResponse))
				resp.Diagnostics.AddError(summary, detail)
				return
			}
			break // already gone, so there is nothing to delete
		}
'''.replace("MARK", MARK)

DELETE_V2 = '''	switch res.StatusCode {
	case 204: MARK
		break
	default:
		if GONE(res.RawResponse) {
			break // already gone, so there is nothing to delete
		}
'''.replace("MARK", MARK)

# Which test belongs to which resource, and what its payload field is called.
# A client path carries the service id, so a client whose service was deleted
# answers with the service's 403; its clients went with the service.
# gone test, payload field, and the identifier Read already has in scope.
RESOURCES = {
    "internal/provider/service_resource.go": ("serviceIsGone", "Service", "ServiceID", SERVICE_CONFIRM),
    "internal/provider/client_resource.go": ("clientOrServiceIsGone", "Client", "ClientID", CLIENT_CONFIRM),
}


def fill(text, gone, payload, idfield="", confirm=""):
    return (text.replace("CONFIRM", confirm)
                .replace("GONE", gone)
                .replace("PAYLOAD_LOWER", payload.lower())
                .replace("IDFIELD", idfield)
                .replace("PAYLOAD", payload))


def apply_one(out, name, befores, after, check, missing):
    """Replace the first matching form, or report. Returns the new text and
    whether a site was counted."""
    if after in out:
        return out, True
    for before in befores:
        if before in out:
            if check:
                missing.append(name + ": still decides from the status code alone")
                return out, False
            return out.replace(before, after, 1), True
    missing.append(name + ": neither the patched nor the original form was found")
    return out, False


def main():
    check = "--check" in sys.argv
    failed = False
    sites = 0

    for path in DATA_SOURCES:
        src = open(path).read()
        if DS_AFTER in src:
            sites += 1
            continue
        if DS_BEFORE not in src:
            print(path + ": neither the patched nor the original form was found", file=sys.stderr)
            failed = True
            continue
        if check:
            print(path + ": a missing service is still reported as a bare 403", file=sys.stderr)
            failed = True
            continue
        open(path, "w").write(src.replace(DS_BEFORE, DS_AFTER, 1))
        sites += 1

    for path, (gone, payload, idfield, confirm) in RESOURCES.items():
        src = open(path).read()
        out = src
        missing = []

        out, ok = apply_one(
            out, "Read",
            [fill(READ_V2, gone, payload), fill(READ_V1, gone, payload), fill(READ_PRISTINE, gone, payload)],
            fill(READ_AFTER, gone, payload, idfield), check, missing)
        sites += ok

        before_create, after_create = CREATE[path]
        out, ok = apply_one(
            out, "Create", [before_create], after_create, check, missing)
        sites += ok

        out, ok = apply_one(
            out, "Delete",
            [fill(DELETE_V4, gone, payload), fill(DELETE_V3, gone, payload), fill(DELETE_V2, gone, payload), DELETE_V1, DELETE_PRISTINE],
            fill(DELETE_AFTER, gone, payload, idfield, confirm), check, missing)
        sites += ok

        for m in missing:
            print(path + ": " + m, file=sys.stderr)
            failed = True

        if out != src:
            open(path, "w").write(out)

    if failed:
        if check:
            print("\nRun scripts/patch-missing-service.py to reapply.", file=sys.stderr)
        sys.exit(1)

    print("ok: a missing resource is judged from the body in %d places" % sites)


if __name__ == "__main__":
    main()
