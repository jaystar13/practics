package com.jaystar.social.security.oauth2;

import com.jaystar.social.utils.CookieUtil;
import com.jaystar.social.utils.cipher.Aes256;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static java.util.Objects.isNull;

@Component
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    public static final Duration OAUTH2_COOKIE_EXPIRY = Duration.ofMinutes(5);

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getCookie(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {
        if (isNull(authorizationRequest)) {
            removeAuthorizationRequest(request, response);
            return;
        }

        CookieUtil.addCookie(response, OAUTH2_COOKIE_NAME, encrypt(authorizationRequest), OAUTH2_COOKIE_EXPIRY);

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.hasText(redirectUriAfterLogin)) {
            CookieUtil.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, OAUTH2_COOKIE_EXPIRY);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = getCookie(request);
        CookieUtil.removeCookie(request, response, OAUTH2_COOKIE_NAME);
        return oAuth2AuthorizationRequest;
    }

    private OAuth2AuthorizationRequest getCookie(HttpServletRequest request) {
        return CookieUtil.getCookie(request, OAUTH2_COOKIE_NAME)
                .map(this::decrypt)
                .orElse(null);
    }

    private String encrypt(OAuth2AuthorizationRequest authorizationRequest) {
        byte[] bytes = SerializationUtils.serialize(authorizationRequest);
        return Aes256.encrypt(bytes);
    }

    private OAuth2AuthorizationRequest decrypt(Cookie cookie) {
        byte[] bytes = Aes256.decrypt(cookie.getValue().getBytes(StandardCharsets.UTF_8));
        return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(bytes);
    }
}
