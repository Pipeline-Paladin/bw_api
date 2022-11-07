package bw_api.auth.admin

import future.keywords.in

default allow = false

allow {
    contains(input.path, "/api/admin/")
    "/bw_apiAdmin" in token.payload.groups
}

token = {"payload": payload} {
	[_, payload, _] := io.jwt.decode(input.token)
}
