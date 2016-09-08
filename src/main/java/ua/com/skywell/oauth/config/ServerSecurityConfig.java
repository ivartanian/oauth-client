package ua.com.skywell.oauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.RequestContextFilter;

import javax.servlet.Filter;
import java.security.Principal;

/**
 * Created by viv on 02.09.2016.
 */
@Configuration
@EnableWebSecurity(debug = true)
@RestController
@EnableOAuth2Client
public class ServerSecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2ClientContext oauth2ClientContext;
    private final OAuth2ClientContextFilter oAuth2ClientContextFilter;

    @Autowired
    public ServerSecurityConfig(OAuth2ClientContext oauth2ClientContext, OAuth2ClientContextFilter oAuth2ClientContextFilter) {
        this.oauth2ClientContext = oauth2ClientContext;
        this.oAuth2ClientContextFilter = oAuth2ClientContextFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("user").roles("USER");
    }

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**").permitAll().anyRequest()
                .authenticated().and().exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
                .logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(requestContextFilter(), OAuth2ClientAuthenticationProcessingFilter.class)
                .addFilterBefore(oAuth2ClientContextFilter, LogoutFilter.class);
        // @formatter:on
    }

    private Filter ssoFilter() {
        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
        OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
        facebookFilter.setRestTemplate(facebookTemplate);
        facebookFilter.setTokenServices(inMemoryTokenServices());
        return facebookFilter;
    }

    @Bean
    public RequestContextFilter requestContextFilter() {
        return new RequestContextFilter();
    }

    @Bean
    public AuthorizationCodeResourceDetails facebook() {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
//        details.setClientId("233668646673605");
//        details.setClientSecret("33b17e044ee6a4fa383f46ec6e28ea1d");
        details.setClientId("633144140184253");
        details.setClientSecret("d55483e709a9e2146e1a40528f64f4ef");
        details.setAccessTokenUri("https://graph.facebook.com/oauth/access_token");
        details.setUserAuthorizationUri("https://www.facebook.com/dialog/oauth");
        details.setTokenName("oauth_token");
        details.setAuthenticationScheme(AuthenticationScheme.query);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        details.setUseCurrentUri(true);
        return details;
    }

    @Bean
    public DefaultTokenServices inMemoryTokenServices() {
        InMemoryTokenStore tok = new InMemoryTokenStore();
        DefaultTokenServices tokenService = new DefaultTokenServices();
        tokenService.setTokenStore(tok);
        return tokenService;
    }

}