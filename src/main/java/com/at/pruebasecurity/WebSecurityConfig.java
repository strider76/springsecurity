package com.at.pruebasecurity;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/","/home").permitAll()
                    .antMatchers("/hello").hasAnyRole("USER", "ADMIN")
                    .antMatchers("/admin").hasRole("ADMIN")

                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
//                .defaultSuccessUrl("/hello")
                    .failureForwardUrl("/login")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll()
                    .and()
                .exceptionHandling().accessDeniedPage("/denied");
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        List<UserDetails> usuarios = new ArrayList<>();
        for (int i=1;i<=4;i++) {
            UserDetails userDetails = User.withUsername("user" + i)
                    .password(passwordEncoder.encode("password" + i))
                    .roles(("USER"))
                    .build();
            usuarios.add(userDetails);
        }
        UserDetails userDetails = User.withUsername("admin")
                .password(passwordEncoder.encode("admin" ))
                .roles(("ADMIN"))
                .build();
        usuarios.add(userDetails);

//        UserDetails userDetails = User.withUsername("user")
//                .password(passwordEncoder.encode("password"))
//                .roles(("USER"))
//                .build();


        return new InMemoryUserDetailsManager(usuarios);
    }
}
