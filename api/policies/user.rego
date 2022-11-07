package bw_api.auth.user

import future.keywords.in

default allow = false

allow {
    contains(input.path, "/api/user/")
    "/bw_apiUser" in token.payload.groups
}

allow {
    contains(input.path, "/api/user/")
    "/bw_apiAdmin" in token.payload.groups
}

token = {"payload": payload} {
	[_, payload, _] := io.jwt.decode(input.token)
}
