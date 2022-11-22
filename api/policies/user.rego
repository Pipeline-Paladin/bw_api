package bw-spa.auth.user

import future.keywords.in

default allow = false

allow {
    contains(input.path, "/api/user/")
    "/bw-spaUser" in token.payload.groups
}

allow {
    contains(input.path, "/api/user/")
    "/bw-spaAdmin" in token.payload.groups
}

token = {"payload": payload} {
	[_, payload, _] := io.jwt.decode(input.token)
}
