/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package demo;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public UserDetailsService userDetailsServiceBean() {
        try {
            return super.userDetailsServiceBean();
        } catch (Exception e) {
            LOGGER.error("Error configuring userdetailsbean", e);
            return null;
        }
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Configuration
    @EnableResourceServer
    static class OauthResourceServerConfiguration extends ResourceServerConfigurerAdapter {


        @Autowired
        AuthenticationManager authenticationManager;

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            resources.tokenServices(defaultTokenServices()).authenticationManager(authenticationManager);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/api/**").access("hasRole('ROLE_ADMIN')")
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        }

        @Bean
        public JwtTokenStore tokenStore() {
            JwtTokenStore store = new JwtTokenStore(tokenEnhancer());
            return store;
        }

        @Bean
        public JwtAccessTokenConverter tokenEnhancer() {
            final JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
            jwtAccessTokenConverter.setSigningKey("xxxx");
            return jwtAccessTokenConverter;
        }

        @Bean
        public TokenEnhancerChain tokenEnhancerChain() {
            final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            tokenEnhancerChain.setTokenEnhancers(Arrays.asList(new CustomTokenEnhancer(), tokenEnhancer()));
            return tokenEnhancerChain;
        }

        @Bean
        public ResourceServerTokenServices defaultTokenServices() {
            final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setTokenEnhancer(tokenEnhancerChain());
            defaultTokenServices.setTokenStore(tokenStore());
            return defaultTokenServices;
        }

        private static class CustomTokenEnhancer implements TokenEnhancer {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                final Map<String, Object> additionalInfo = new HashMap<>();
                additionalInfo.put("userId", accessToken.getAdditionalInformation().get("userId"));
                additionalInfo.put("companyId", accessToken.getAdditionalInformation().get("companyId"));
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
                return accessToken;
            }

        }
    }
}