import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import {PredictionComponent} from './prediction/prediction.component';
import {SigninComponent} from './signin/signin.component';

const routes: Routes = [
    {
        path: '',
        component: PredictionComponent
    },
    {
        path: 'signin',
        component: SigninComponent
    }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }

