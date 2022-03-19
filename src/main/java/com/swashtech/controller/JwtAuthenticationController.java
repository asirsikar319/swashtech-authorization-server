package com.swashtech.controller;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.swashtech.model.DAOUser;
import com.swashtech.model.JwtRequest;
import com.swashtech.model.JwtResponse;
import com.swashtech.model.UserDTO;
import com.swashtech.security.config.JwtTokenUtil;
import com.swashtech.service.JwtUserDetailsService;
import com.swashtech.utils.JSchemaUtility;

import io.swagger.annotations.ApiOperation;

@RestController
@CrossOrigin
public class JwtAuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private JwtUserDetailsService userDetailsService;

	@Autowired
	private JSchemaUtility jSchemaUtility;

	@ApiOperation(value = "authenticate", response = Iterable.class)
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST, produces = "application/json")
	public ResponseEntity<String> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest)
			throws Exception {

		ResponseEntity<String> response = null;

		JSONObject jInput = new JSONObject(authenticationRequest);
		JSONObject schema = jSchemaUtility.readResourceFile("authenticate.json");
		JSONObject schemaOutput = jSchemaUtility.validateSchema(schema, jInput);
		if (schemaOutput != null && "Success".equals(schemaOutput.getString("status"))) {
			authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

			final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

			final JwtResponse jwtResponse = jwtTokenUtil.generateToken(userDetails,
					authenticationRequest.getSignalias());
			response = new ResponseEntity<String>(new JSONObject(jwtResponse).toString(), HttpStatus.OK);
		} else {
			response = new ResponseEntity<String>(schemaOutput.toString(), HttpStatus.BAD_REQUEST);
		}

		return response;
	}

	@ApiOperation(value = "register", response = Iterable.class)
	@RequestMapping(value = "/register", method = RequestMethod.POST, produces = "application/json")
	public ResponseEntity<String> saveUser(@RequestBody UserDTO user) throws Exception {

		ResponseEntity<String> response = null;

		JSONObject jInput = new JSONObject(user);
		JSONObject schema = jSchemaUtility.readResourceFile("register.json");
		JSONObject schemaOutput = jSchemaUtility.validateSchema(schema, jInput);
		if (schemaOutput != null && "Success".equals(schemaOutput.getString("status"))) {
			DAOUser daoUser = userDetailsService.save(user);
			response = new ResponseEntity<String>(new JSONObject().put("username", daoUser.getUsername()).toString(), HttpStatus.OK);
		} else {
			response = new ResponseEntity<String>(schemaOutput.toString(), HttpStatus.BAD_REQUEST);
		}

		return response;
	}

	private void authenticate(String username, String password) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}