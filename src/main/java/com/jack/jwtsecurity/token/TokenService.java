package com.jack.jwtsecurity.token;


import com.jack.jwtsecurity.user.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.NotFoundException;

import java.util.List;

@ApplicationScoped
public class TokenService {

    final static String BEARER_TOKEN_PREFIX = "Bearer ";

    @Transactional
    public void saveToken(String strToken, User user) {
        Token token = new Token();
        token.token = strToken;
        token.user = user;

        token.persist();
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = Token.find("user.id = ?1 and revoked = ?2 and expired = ?3", user.id, false, false).list();
        if (validUserTokens.isEmpty()) return;

        validUserTokens.forEach(token -> {
            token.revoked = true;
            token.expired = true;
        });
        Token.persist(validUserTokens);
    }

    public Token findToken(String strToken) {
        Token token = Token.find("token", strToken).firstResult();
        if (token == null || token.expired || token.revoked) {
            throw new NotFoundException("Token not found, or expired, or revoked");
        }
        return token;
    }

    @Transactional
    public void disableToken(Token token) {
        token.revoked = true;
        token.expired = true;

        token.persist();
    }
}
