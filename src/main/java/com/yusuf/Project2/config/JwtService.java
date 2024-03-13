package com.yusuf.Project2.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "38bb08091d9e3b3b7d47435778c87d09899a9fb03f4023eb43b8b40a2e37ce21";
    public String extractUserName(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    public<T> T extractClaim(String token, Function<Claims,T> claimResolver){
        final Claims claims = extractALlClaims(token);
        return claimResolver.apply(claims);
    }
    public String generateToken(
            Map<String,Object> extractClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60  * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    // to generate token w/o claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(),userDetails);
    }
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }
    private Claims extractALlClaims (String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
