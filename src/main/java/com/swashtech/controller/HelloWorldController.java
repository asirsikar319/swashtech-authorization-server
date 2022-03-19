package com.swashtech.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

	@RequestMapping("/validateUser")
	public Principal user(Principal user) {
		return user;
	}

	@RequestMapping({ "/hello" })
	public String firstPage() {
		return "Hello World";
	}

}