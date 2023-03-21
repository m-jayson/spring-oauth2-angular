import { Component } from '@angular/core';
import { AuthConfigServiceService } from './auth-config.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'auth-ui';
  constructor(private readonly authConfigServiceService: AuthConfigServiceService){}
}
