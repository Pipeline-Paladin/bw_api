import { Component, OnInit } from "@angular/core";
import {ApiService} from "../services/api.service";

@Component({
    selector: "app-status",
    templateUrl: "./status.component.html",
    styleUrls: ["./status.component.css"]
})
export class StatusComponent implements OnInit {

    constructor(private api: ApiService) { }

    message: string = "Querying api"

    async ngOnInit() {
        const res = await this.api.getStatus()
        res.subscribe((data) => {
            this.message = data.message
        }, (err) => {
            this.message = err.error.message
        });
    }
}
