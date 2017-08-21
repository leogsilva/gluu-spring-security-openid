package com.leogsilva.security;

import java.io.IOException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.client.RestTemplate;

public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {
    public OAuth2RestOperations restTemplate;

    @Value("${gluu.userInfoUri}")
    private String userInfoUri;

    @Autowired
    private OAuth2ProtectedResourceDetails resource;

    public OpenIdConnectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(new NoopAuthenticationManager());
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        ServletRequest request = req;
        ServletResponse response = res;
        super.doFilter(req, res, chain);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        OAuth2AccessToken accessToken;
        try {
            accessToken = restTemplate.getAccessToken();
        } catch (final OAuth2Exception e) {
            throw new BadCredentialsException("Could not obtain access token", e);
        }
        try {
            Map userInfo = getUserInfo(accessToken);
            final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
            final Jwt tokenDecoded = JwtHelper.decode(idToken);
            System.out.println("===== : " + tokenDecoded.getClaims());

            final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);

            final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(authInfo, userInfo, accessToken);
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        } catch (final InvalidTokenException e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        } catch (IOException e) {
            throw new BadCredentialsException("Error reading User info", e);
        }

    }

    public void setRestTemplate(OAuth2RestTemplate restTemplate2) {
        restTemplate = restTemplate2;

    }

    public Map getUserInfo(OAuth2AccessToken accessToken) throws IOException {
        RestTemplate template = new RestTemplate();
        String json = template.getForObject(userInfoUri + "?access_token=" + accessToken.getValue(),  String.class);
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Map.class);
    }


    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }
}
