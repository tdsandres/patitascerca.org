import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ButtonFilterComponent } from './button-filter.component';

describe('ButtonFilterComponent', () => {
  let component: ButtonFilterComponent;
  let fixture: ComponentFixture<ButtonFilterComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ButtonFilterComponent]
    });
    fixture = TestBed.createComponent(ButtonFilterComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
