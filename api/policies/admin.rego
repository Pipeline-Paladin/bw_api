package taime.auth.admin

import future.keywords.in

default allow = false

allow {
    contains(input.path, "/api/admin/")
    "/taimeAdmin" in token.payload.groups
}

token = {"payload": payload} {
	[_, payload, _] := io.jwt.decode(input.token)
}
