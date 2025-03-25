package com.jack.jwtsecurity.token;


import com.jack.jwtsecurity.token.exception.TokenNotFoundException;
import com.jack.jwtsecurity.user.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class TokenService {

    final static String BEARER_TOKEN_PREFIX = "Bearer ";

    @Transactional
    public void saveToken(String strToken, User user, TokenSpec tokenSpec) {
        Token token = new Token();
        token.token = strToken;
        token.user = user;
        token.tokenSpec = tokenSpec;

        token.persist();
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = Token.find("user.id = ?1 and revoked = ?2 ", user.id, false).list();
        if (validUserTokens.isEmpty()) return;

        validUserTokens.forEach(token -> {
            token.revoked = true;
//            token.expired = true;
        });
        Token.persist(validUserTokens);
    }

    @Transactional
    public void revokeAllUserAccessTokens(User user) {
        List<Token> validUserTokens = Token.find("user.id = ?1 and revoked = ?2 and tokenspec = ?4", user.id, false, TokenSpec.ACCESS_TOKEN).list();
        if (validUserTokens.isEmpty()) return;

        validUserTokens.forEach(token -> {
            token.revoked = true;
//            token.expired = true;
        });
        Token.persist(validUserTokens);
    }

    public Token findToken(String strToken) {
        Token token = Token.find("token", strToken).firstResult();
        if (token == null || token.revoked) {
            throw new TokenNotFoundException("Token not found, or expired, or revoked");
        }
        return token;
    }

    @Transactional
    public void disableToken(Token token) {
        token.revoked = true;
//        token.expired = true;

        token.persist();
    }

    public String getBearerToken(String authHeader) {

        if (authHeader== null || !authHeader.startsWith(BEARER_TOKEN_PREFIX)) {
            throw new TokenNotFoundException("Bearer token not found");
        }
           return authHeader.substring(BEARER_TOKEN_PREFIX.length());
    }
}
