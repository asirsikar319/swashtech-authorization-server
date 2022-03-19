package com.swashtech.security.config;

import java.io.Serializable;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.Function;

import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.swashtech.model.JwtResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -2550185165626007488L;

	@Value("${app.security.jwt.private-key-passphrase}")
	private String privateKeyPassphrase;

	@Autowired
	private KeyStore keyStore;

	@Autowired
	private KeyStore keyStore2;

	public RSAPrivateKey jwtSigningKey(String keyAlias) {
		try {
			Key key = keyStore.getKey(keyAlias, privateKeyPassphrase.toCharArray());
			if (key instanceof RSAPrivateKey) {
				return (RSAPrivateKey) key;
			}
		} catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}

		throw new IllegalArgumentException("Unable to load private key");
	}

	public RSAPublicKey jwtValidationKey(String keyAlias) {
		try {
			X509Certificate certificate = (X509Certificate) keyStore2.getCertificate(keyAlias);
			PublicKey publicKey = certificate.getPublicKey();

			if (publicKey instanceof RSAPublicKey && certificate.getNotAfter().before(new Date())) {
				return (RSAPublicKey) publicKey;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		throw new IllegalArgumentException("Unable to load RSA public key");
	}

	// retrieve username from jwt token
	public String getUsernameFromToken(String token, String keyAlias) {
		return getClaimFromToken(token, Claims::getSubject, keyAlias);
	}

	// retrieve expiration date from jwt token
	public Date getExpirationDateFromToken(String token, String keyAlias) {
		return getClaimFromToken(token, Claims::getExpiration, keyAlias);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver, String keyAlias) {
		final Claims claims = getAllClaimsFromToken(token, keyAlias);
		return claimsResolver.apply(claims);
	}

	// for retrieveing any information from token we will need the secret key
	private Claims getAllClaimsFromToken(String token, String keyAlias) {
		return Jwts.parser().setSigningKey(jwtValidationKey(keyAlias)).parseClaimsJws(token).getBody();
	}

	// check if the token has expired
	private Boolean isTokenExpired(String token, String keyAlias) {
		final Date expiration = getExpirationDateFromToken(token, keyAlias);
		return expiration.before(new Date());
	}

	// generate token for user
	public JwtResponse generateToken(UserDetails userDetails, String keyAlias) {
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims, userDetails.getUsername(), keyAlias);
	}

	// while creating the token -
	// 1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
	// 2. Sign the JWT using the HS512 algorithm and secret key.
	// 3. According to JWS Compact
	// Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
	// compaction of the JWT to a URL-safe string
	private JwtResponse doGenerateToken(Map<String, Object> claims, String subject, String keyAlias) {
		Calendar calendar = Calendar.getInstance();
		calendar.setTimeInMillis(Instant.now().toEpochMilli());
		calendar.add(Calendar.MINUTE, 2);
		Date expiry = new Date(calendar.getTimeInMillis());
		String token = Jwts.builder().setClaims(claims).setSubject(subject)
				.setIssuedAt(new Date(System.currentTimeMillis())).setExpiration(expiry)
				.signWith(SignatureAlgorithm.RS256, jwtSigningKey(keyAlias)).compact();
		SimpleDateFormat sd = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
		sd.setTimeZone(TimeZone.getTimeZone("IST"));
		JwtResponse jwtResponse = new JwtResponse(token, sd.format(expiry));
		return jwtResponse;
	}

	// validate token
	public Boolean validateToken(String token, UserDetails userDetails, String keyAlias) {
		final String username = getUsernameFromToken(token, keyAlias);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token, keyAlias));
	}
}