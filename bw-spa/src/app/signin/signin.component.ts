import { Component, OnInit } from '@angular/core';
import {Router} from '@angular/router';
import {AuthService} from '../services/auth.service';

@Component({
  selector: 'app-signin',
  templateUrl: './signin.component.html',
  styleUrls: ['./signin.component.css']
})
export class SigninComponent implements OnInit {

  constructor(private readonly _router: Router, private readonly _authService: AuthService) { }

  async ngOnInit() {
    await this._authService.manager.signinCallback();
    this._router.navigate([''])
  }

}
