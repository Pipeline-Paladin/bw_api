import { Injectable } from "@angular/core";
import { User, UserManager } from "oidc-client-ts";

@Injectable({
    providedIn: "root"
})
export class AuthService {

    manager : UserManager;

    constructor() { 
        this.manager = new UserManager({
            authority: "http://localhost:8080/realms/taime",
            client_id: "taime",
            redirect_uri: "http://localhost:4200/signin",
            response_type: 'code',
            scope: "profile email groups",
            post_logout_redirect_uri: "http://localhost:4200",
            silent_redirect_uri: "http://localhost:4200/signin-silent"
        });
    }

    public getUser()
    {
        return this.manager.getUser();
    }

    public login()
    {
        return this.manager.signinRedirect();
    }
}
