package taime.auth.user

import future.keywords.in

default allow = false

allow {
    contains(input.path, "/api/user/")
    "/taimeUser" in token.payload.groups
}

allow {
    contains(input.path, "/api/user/")
    "/taimeAdmin" in token.payload.groups
}

token = {"payload": payload} {
	[_, payload, _] := io.jwt.decode(input.token)
}
