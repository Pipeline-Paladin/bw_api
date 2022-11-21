import { Injectable } from '@angular/core';
import {AuthService} from './auth.service';
import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';

@Injectable({
    providedIn: 'root'
})
export class ApiService {

    constructor(private httpClient: HttpClient, private authService: AuthService) { }


    public async getDay() {
        const user = await this.authService.getUser();

        const headers = new HttpHeaders({
            Accept: 'application/json',
            Authorization: 'Bearer ' + user?.access_token
        });

        return this.httpClient.get<Day>("http://localhost:8081/api/user/day", {headers: headers});
    }

    public async getStatus() {
        const user = await this.authService.getUser();

        const headers = new HttpHeaders({
            Accept: 'application/json',
            Authorization: 'Bearer ' + user?.access_token
        });

        return this.httpClient.get<Day>("http://localhost:8081/api/admin/status", {headers: headers});
    }
}

interface Day
{
    status: number;
    message: string;
}
