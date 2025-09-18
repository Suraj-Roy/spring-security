package com.notes.springsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountsController {

    @GetMapping("/name")
    public ResponseEntity<String> getName(){
        return ResponseEntity.status(HttpStatus.OK).body("My name is suraj");
    }
}
