package com.example.demo;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.Charset;
import java.security.Principal;

@Component
@Configuration
public class AuthenticationApi {

    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }

    @Value("${AUTHENTICATION_API}")
    private String authenticationUri;

    public ResponseEntity<Principal> authenticate(String username, String pass) {
       // HttpEntity<Principal> entity = new HttpEntity<Principal>(createHeaders(username, pass))
        //return restTemplate().exchange(authenticationUri, HttpMethod.GET, entity, Principal.class);
        if (username.equals("user"))
            return ResponseEntity.ok(new FakePrincipal());
        else
            return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
    }



    HttpHeaders createHeaders(String username, String password) {
        HttpHeaders acceptHeaders = new HttpHeaders() {
            {
                set(com.google.common.net.HttpHeaders.ACCEPT,
                        MediaType.APPLICATION_JSON.toString());
            }
        };
        String authorization = username + ":" + password;
        String basic = new String(Base64.encodeBase64
                (authorization.getBytes(Charset.forName("US-ASCII"))));
        acceptHeaders.set("Authorization", "Basic " + basic);

        return acceptHeaders;
    }

}