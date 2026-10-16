#!/usr/bin/env python3
"""Treat a service Authlete says does not exist as gone, not as an error.

Authlete answers a request for a missing service with 403 and resultCode
A458203, not 404. The generated code only knows 404, so a service deleted
outside Terraform wedged the resource: every plan failed with "unexpected
response code 403" until someone ran `terraform state rm` by hand.

This inserts the extra check into the generated Read and Delete. The test for
it is serviceIsGone in internal/provider/missing_service.go, which Speakeasy
does not generate and does not touch.

  patch-missing-service.py           apply
  patch-missing-service.py --check   verify, non-zero if any site is unpatched
"""
import sys

# The client paths carry the service id too, so a client whose service was
# deleted gets the same 403 rather than a 404. Its clients are gone with it.
PATHS = [
    "internal/provider/service_resource.go",
    "internal/provider/client_resource.go",
]

# A data source cannot drop itself from state the way a resource can, because
# it was never in state. Asking for a service that does not exist is an error;
# what matters is that the error says so instead of printing a bare 403.
DATA_SOURCES = [
    "internal/provider/service_data_source.go",
    "internal/provider/client_data_source.go",
]

DS_BEFORE = """	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
"""
DS_AFTER = """	if serviceIsGone(res.RawResponse) { // scripts/patch-missing-service.py
		summary, detail := serviceGoneMessage(fmt.Sprintf("%v", request.ServiceID))
		resp.Diagnostics.AddError(summary, detail)
		return
	}
	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
"""

# Read: 404 already removes the resource; 403 + A458203 means the same thing.
READ_BEFORE = """	if res.StatusCode == 404 {
		resp.State.RemoveResource(ctx)
		return
	}
	if res.StatusCode != 200 {
"""
READ_AFTER = """	if res.StatusCode == 404 {
		resp.State.RemoveResource(ctx)
		return
	}
	if serviceIsGone(res.RawResponse) { // scripts/patch-missing-service.py
		resp.State.RemoveResource(ctx)
		return
	}
	if res.StatusCode != 200 {
"""

# Delete: deleting something already deleted is a success, not a failure.
DELETE_BEFORE = """	switch res.StatusCode {
	case 204, 404:
		break
	default:
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
"""
DELETE_AFTER = """	switch res.StatusCode {
	case 204, 404:
		break
	default:
		if serviceIsGone(res.RawResponse) { // scripts/patch-missing-service.py
			break // already gone, so there is nothing to delete
		}
		resp.Diagnostics.AddError(fmt.Sprintf("unexpected response from API. Got an unexpected response code %v", res.StatusCode), debugResponse(res.RawResponse))
		return
	}
"""

EDITS = [("Read", READ_BEFORE, READ_AFTER), ("Delete", DELETE_BEFORE, DELETE_AFTER)]


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
            print(f"{path}: neither the patched nor the original form was found", file=sys.stderr)
            failed = True
            continue
        if check:
            print(f"{path}: a missing service is still reported as a bare 403", file=sys.stderr)
            failed = True
            continue
        open(path, "w").write(src.replace(DS_BEFORE, DS_AFTER, 1))
        sites += 1

    for path in PATHS:
        src = open(path).read()
        out = src
        missing = []

        for name, before, after in EDITS:
            if after in out:
                sites += 1
                continue
            if before not in out:
                missing.append(f"{name}: neither the patched nor the original form was found")
                continue
            if check:
                missing.append(f"{name}: a missing service is still reported as an error")
                continue
            out = out.replace(before, after, 1)
            sites += 1

        for m in missing:
            print(f"{path}: {m}", file=sys.stderr)
            failed = True

        if out != src:
            open(path, "w").write(out)

    if failed:
        if check:
            print("\nRun scripts/patch-missing-service.py to reapply.", file=sys.stderr)
        sys.exit(1)
    print(f"ok: a missing service is treated as gone in {sites} places")


if __name__ == "__main__":
    main()
