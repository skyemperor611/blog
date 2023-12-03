package com.blog.my.config.jwt;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

import static java.util.Collections.emptyMap;

@Getter
public class JwtFactory {
    private final String subject;
    private final Date issuedAt;
    private final Date expiration;
    private final Map<String, Object> claims;

    // Private constructor
    private JwtFactory(String subject, Date issuedAt, Date expiration, Map<String, Object> claims) {
        this.subject = subject;
        this.issuedAt = issuedAt;
        this.expiration = expiration;
        this.claims = claims;
    }

    // Static method to create the default JwtFactory instance
    public static JwtFactory withDefaultValues() {
        return JwtFactory.builder()
                .subject("test@email.com")
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + Duration.ofDays(14).toMillis()))
                .claims(emptyMap())
                .build();
    }

    // Create token method
    public String createToken(JwtProperties jwtProperties) {
        return Jwts.builder()
                .setSubject(subject)
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .addClaims(claims)
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();
    }

    // Builder static inner class
    public static class Builder {
        private String subject;
        private Date issuedAt;
        private Date expiration;
        private Map<String, Object> claims;

        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public Builder issuedAt(Date issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder expiration(Date expiration) {
            this.expiration = expiration;
            return this;
        }

        public Builder claims(Map<String, Object> claims) {
            this.claims = claims;
            return this;
        }

        public JwtFactory build() {
            return new JwtFactory(subject, issuedAt, expiration, claims);
        }
    }

    // Static method to get an instance of the Builder
    public static Builder builder() {
        return new Builder();
    }
}
