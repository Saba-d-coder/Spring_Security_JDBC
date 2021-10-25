package com.springsecurity.jdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
//                passing true value as our users table doesn't contain enabled field
                .usersByUsernameQuery(
                        "SELECT username, password, true FROM user WHERE username=?")
//                users role can be either ROLE_ADMIN or ROLE_USER
                .authoritiesByUsernameQuery(
                        "SELECT username, role FROM user WHERE username=?");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/").permitAll()
                .and().formLogin();
    }

    //    disabling password encoder
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /*
     * @Override protected void configure(AuthenticationManagerBuilder auth) throws
     * Exception { auth.jdbcAuthentication() .dataSource(dataSource)
     * .withDefaultSchema() .withUser( User.withUsername("user") .password("user")
     * .roles("USER") ) .withUser( User.withUsername("admin") .password("admin")
     * .roles("ADMIN") ); }
     */

}
