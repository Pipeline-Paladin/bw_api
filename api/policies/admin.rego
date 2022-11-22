package bw-spa.auth.admin

import future.keywords.in

default allow = false

allow {
    contains(input.path, "/api/admin/")
    "/bw-spaAdmin" in token.payload.groups
}

token = {"payload": payload} {
	[_, payload, _] := io.jwt.decode(input.token)
}
