package com.sample.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/partner")
public class PartnerController {


    @GetMapping
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("works");
    }

}
