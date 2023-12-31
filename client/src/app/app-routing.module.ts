import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { BrowserModule } from '@angular/platform-browser';
import { AuthComponent } from './views/auth/auth.component';
import { HomeComponent } from './views/home/home.component';


const routes: Routes = [
    { path: '', component: AuthComponent },
    { path: 'home', component: HomeComponent }
];

@NgModule({
    imports: [
        BrowserModule,
        RouterModule.forRoot(routes)
    ],
    exports: [RouterModule]
})

export class AppRoutingModule { }