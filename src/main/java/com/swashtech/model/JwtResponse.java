package com.swashtech.model;

import java.io.Serializable;
import java.util.Date;

public class JwtResponse implements Serializable {

	private static final long serialVersionUID = -8091879091924046844L;
	private final String token;
	private final String validUpto;

	public JwtResponse(String token, String validUpto) {
		this.token = token;
		this.validUpto = validUpto;
	}

	public String getToken() {
		return this.token;
	}

	public String getValidUpto() {
		return validUpto;
	}

}