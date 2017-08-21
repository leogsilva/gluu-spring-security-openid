package com.leogsilva.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

@Configuration
@EnableOAuth2Client
public class GluuOpenIdConnectConfig {
    @Value("${gluu.clientId}")
    private String clientId;

    @Value("${gluu.clientSecret}")
    private String clientSecret;

    @Value("${gluu.accessTokenUri}")
    private String accessTokenUri;

    @Value("${gluu.userAuthorizationUri}")
    private String userAuthorizationUri;

    @Value("${gluu.redirectUri}")
    private String redirectUri;

    @Value("${gluu.userInfoUri")
    private String userInfoUri;

    @Bean
    public OAuth2ProtectedResourceDetails googleOpenId() {
        final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthorizationUri);
        details.setScope(Arrays.asList("openid", "user_name", "email"));
        details.setPreEstablishedRedirectUri(redirectUri);
        details.setUseCurrentUri(false);
        details.setClientAuthenticationScheme(AuthenticationScheme.header);
        return details;
    }

    @Bean
    public OAuth2RestTemplate googleOpenIdTemplate(final OAuth2ClientContext clientContext) {
        final OAuth2RestTemplate template = new OAuth2RestTemplate(googleOpenId(), clientContext);
        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
          Arrays.<AccessTokenProvider>asList(new GluuAuthorizationCodeAccessTokenProvider())
        );
        template.setAccessTokenProvider(accessTokenProvider);
        return template;
    }

}
