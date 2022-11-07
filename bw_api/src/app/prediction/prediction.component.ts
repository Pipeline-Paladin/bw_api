import { Component, OnInit } from "@angular/core";
import {ApiService} from "../services/api.service";
import {AuthService} from "../services/auth.service";

@Component({
    selector: "app-prediction",
    templateUrl: "./prediction.component.html",
    styleUrls: ["./prediction.component.css"]
})
export class PredictionComponent implements OnInit {
    message  = "";
    auth : AuthService;

    constructor(auth: AuthService, private api: ApiService) {
        this.auth = auth;
    }

    async ngOnInit()
    {
        const user = await this.auth.getUser();

        if(user)
        {
            console.log(user.profile)
            this.message = "Querying API...";
            const res = await this.api.getDay();
            res.subscribe(data => {
                this.message = data.message
            });
        }
        else
        {
            this.auth.login();
        }
    }
}
