package net.example.springboot.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${jwtExpiration}")
    private long jwtExpiration;
    @Value("${refreshExpiration}")
    private long refreshExpiration;
    private static final String SECRET_KEY = "367639792442264529482B4D6251655468576D5A7134743777217A25432A462D";
    public String extractEmail(String jwt){
        return extractClaim(jwt, Claims::getSubject);
    }
    public <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver){
        Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }
    public Claims extractAllClaims(String jwt){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }
    public Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String jwt, UserDetails userDetails){
        String email = extractEmail(jwt);
        return (email.equals(userDetails.getUsername())) && !isTokenExpired(jwt);
    }
    private boolean isTokenExpired(String jwt){
        return extractExpiration(jwt).before(new Date());
    }
    public Date extractExpiration(String jwt){
        return extractClaim(jwt, Claims::getExpiration);
    }

    public String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS256, getSignInKey())
                .compact();
    }
    public String generateToken(UserDetails userDetails){
        return buildToken(new HashMap<>(), userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }
}
