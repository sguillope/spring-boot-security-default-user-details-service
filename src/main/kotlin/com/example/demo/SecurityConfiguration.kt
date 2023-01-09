package com.example.demo

import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider

private const val REQUIRED_ROLE = "PRE_AUTH_USER"

@Configuration
class SecurityConfiguration {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http
            .apply(PreAuthSecurityConfigurer())
            .and()
            .formLogin().disable()
            .csrf().disable()
            .httpBasic().disable()
            .authorizeHttpRequests {
                it.anyRequest().hasRole(REQUIRED_ROLE)
            }
            .build()

    private class PreAuthSecurityConfigurer :
        AbstractHttpConfigurer<PreAuthSecurityConfigurer, HttpSecurity>() {

        override fun configure(http: HttpSecurity) {
            val authenticationManager = http.getSharedObject(AuthenticationManager::class.java)
            val filter = PreAuthFilter().apply {
                setAuthenticationManager(authenticationManager)
            }
            http.addFilter(filter)
                .authenticationProvider(authenticationProvider())
        }

        private fun authenticationProvider(): AuthenticationProvider =
            PreAuthenticatedAuthenticationProvider().apply {
                setPreAuthenticatedUserDetailsService { token ->
                    User.builder()
                        .username(token.principal as String)
                        .roles(REQUIRED_ROLE)
                        .build()
                }
            }
    }

    private class PreAuthFilter : AbstractPreAuthenticatedProcessingFilter() {
        override fun getPreAuthenticatedPrincipal(request: HttpServletRequest): String =
            request.getHeader("X-Auth-Principal")

        override fun getPreAuthenticatedCredentials(request: HttpServletRequest) = "N/A"
    }
}