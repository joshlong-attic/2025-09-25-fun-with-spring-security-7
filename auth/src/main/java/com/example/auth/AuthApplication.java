package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ThrowingCustomizer;
import org.springframework.security.config.annotation.authorization.EnableGlobalMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.Map;

@EnableGlobalMultiFactorAuthentication(authorities = {
        GrantedAuthorities.FACTOR_OTT_AUTHORITY,
        GrantedAuthorities.FACTOR_WEBAUTHN_AUTHORITY})
@SpringBootApplication
public class AuthApplication {

    void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

    @Bean
    InMemoryUserDetailsManager userDetailsManager() {
        return new InMemoryUserDetailsManager(
                User.withUsername("jlong").password("pw").roles("USER").build()
        );
    }

    @Bean
    ThrowingCustomizer<HttpSecurity> httpSecurityCustomizer() {
        return httpSecurity -> {
//            var damf = new DefaultAuthorizationManagerFactory<Object>()
//                    .hasAnyAuthority(
//                            GrantedAuthorities.FACTOR_OTT_AUTHORITY, GrantedAuthorities.FACTOR_WEBAUTHN_AUTHORITY);
            httpSecurity
              //      .authorizeHttpRequests(a -> a.anyRequest().access(damf))
                    .oauth2AuthorizationServer(x -> x.oidc(Customizer.withDefaults()))
                    .webAuthn(x -> x
                            .allowedOrigins("http://localhost:9090")
                            .rpId("localhost")
                            .rpName("bootiful")
                    )
                    .oneTimeTokenLogin(ott -> ott.tokenGenerationSuccessHandler(
                            (OneTimeTokenGenerationSuccessHandler) (_, response,
                                                                    oneTimeToken) -> {

                                var msg = "please go to http://localhost:8080/login/ott?token=" + oneTimeToken.getTokenValue();
                                System.out.println(msg);

                                response.setContentType(MediaType.TEXT_PLAIN_VALUE);
                                response.getWriter().write("you've got console mail!");
                            }
                    ));

        };
    }

}

@Controller
@ResponseBody
class GreetingController {

    @GetMapping("/")
    Map<String, String> greeting(Principal principal) {
        return Map.of("greeting", "hello " + principal.getName());
    }
}