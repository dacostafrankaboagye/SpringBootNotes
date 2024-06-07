
## Lesson 1

- Application Level security
    - Authentication
    - Authorization


- Authentication
    - who is the user

- Authorization
    - whether you are allowed to do something 

- Concepts
    - Authority - something you have - an action you can do
    - Role - something you are - "a badge"

- Granted Authority
    - the interface behind the scenes that represents both role and authority

- Ways in which spring makes you define authentication and authorisation

- Authenticaton

    - Http basic
    - certificate
    - complex ones like - JWT (OAuth2)

- Authorization

    - WEB APPS - Filters
    - Non web apps - Aspects - can be used with web apps

- Note
 - based on adding the "spring security" -> it will configure somethings for you.
 - e.g. generated security password -> every time you start the application
 - :: we can test it if we have at least one endpoint
 - resources : endpoint
 - by default all the resources are secured
    - you have to provide some credentials
        - so you have to know the default authentication (the type): In spring it is the "http basic"
        - in postman - go to the authorisaton-> Basic auth -> 
        - provide the username and password
        - // 
        - the information will be passed through the headers
            - in the headers of the postman - you will see in the header something like this
                - Authorisation : "Basic 83FIFNdud8boWCPIA90B"
                    - it is base64 encoding (not an ENCRYPTION)
                        - go to base64 decode online

```xml

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security<artifactId>
<dependency>

```

- Difference btn encoding, encrypting , hash function

    - Encoding
        - a (function of ) transformation: can be reversed to the original format
        - a mathematical function takes the input -> applies a rule -> give some output
        - you do not need to know / have a secret key

    - Encryption
        - transform an input -> output 
        - to go from output -> input : you always need a secret / secret key : "can be symmetric / asymmetric / public / private / e.t.c"

    - Hash Function
        - you can go from  input -> output
        - but you CANNOT go from output -> input
            - so 2 rules
                - you cannot go from output -> input
                - you can tell if an output corresponds to an input
        - preferred way to store passoword


- How do you create your own credentials
    - creating your own "user details service" : it manages the user details

- User Details Service
    - it is an interface
    - it is what spring understands that holds the user details
    - manager of the user credentials


- In the UserDetailsService

```java
// inside of the org.springframework.security.core.userdetails;

public interface UserDetailsService{
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
}

```

- Note
    - in the above
        - it also has "UserDetails" : also a contract that spring understands as the way the user details is presented : everything to know about the user


- Lets create one (a UserDetailsService) with a simple implementation that spring provides: "InMemoryUserDetailsManager"
    - Note
        - it is mandatory that they have a role
        - We have to manage the passwords as well: we will use a "PasswordEncoder"
    - InMemenory

```java

public class MyWebSecurityConfig{

    // my UserDetailsService so that spring becomes aware of it
    @Bean
    public UserDetailsService userDetailsService(){

        // user-details-service
        var uds = new InMemoryUserDetailsManager();

        // UserDetails
        var u1 = User.withUsername("frank")
            .password("1234")
            .authorities("to read")
            .build();
        
        uds.createUser(u1);

        return uds

    }

    // my PasswordEncoder so that spring becomes aware of it
    @Bean
    public PasswordEncoder passwordEncoder(){
        
        // do not use this password encoder in dev
        return NoOpPasswordEncoder.getInstance();

        // there are many password encoders you can use
            // return new BCryptPasswordEncoder();
            
    }
    
}


/*

- start the application
- there is no more "generated password in the console"
- use the credentails you created: in the authentication in the POSTMAN

-> Some password encoders (PE - password encoder for short)
    - Argon2 PE
    - Delegating PE
    - Lazy PE
    - BCrypt PE
    - Pbkdf2 PE
    - SCrypt PE
    - many more (you can create your own)

*/
```

- The Flow

    - Because it is a web app it starts with a "Filter"

    - Filter which implements the 
      - Http Basic Authenticaton -> delegate to another object
        - Authentication Manager -> delegates to another object
            - Authentication Provider -> uses the "UserDetailsService" & "PasswordEncoder"


## Lesson 2 

    Managing Users

    Authentication Filter -> Authentication manager (only 1) -> finds an approproate Authentication Provider (can be multiple) -> when it needs credentials - it will search and use a UserDetailsService and Password Encoder for validations -> ....

        - You can implement more Authentication providers (AP)
        - Whenever the AP needs username and password -> they must use two components 
            - UserDetailsService
            - Password Encoder

    -> the last step of that chain is to store the Authentication details in the security context


- When using the UserDetailsService
    - spring needs the loadByUsername 

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}

/*

-> parameter : username : unique
-> return type: UserDetails

*/



/*

you can use @Service on the MyUserDetailsService so that, that instance is in the context

*/

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }
}

//-----------------------------------------------------------------------------

/*
or you do that in the security config, make it a bean -> with a new instance like this
*/

// MyUserDetailsService.java

public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }
}

// securit config will look like this


@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService theUserDetailsService() {
        return new MyUserDetailsService();
    }

    @Bean
    public PasswordEncoder thePasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}


//-----------------------------------------------------------------------------



```

---

- Do not use the a stereotype annotation on the interface :
    - the purpose of the stereotype annotation is to create an instance of the class in spring's context

---

- Instead of implementing the user details as part of the entity,  
    - lets do things differently 
        - because: we want to follow the Single Responsibility Principle:
        - if we do something like this

```java
@Entity
@Table
public User implements UserDetails{}

/*

- we are not following the Single Reponsibility Principle
- our class will have two resons to change (first - its an entity, second - its implementing UserDetails)
*/
```

- Well a different choice will be to use a mapper
- but lets use adapting / decorating -> but more of adpater pattern


code review

```java

@AllArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {

    private final MyUserRepository myUserRepository;


    @Override
    public UserDetails loadUserByUsername(String username) {
        var myUser = myUserRepository.findUserByUsername(username);

        return myUser
                .map(MyUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found: " + username));

    }
}


```


```java

@AllArgsConstructor
public class MyUserDetails implements UserDetails {

    private final MyUser myUser;

    @Override
    public String getPassword() {
        return myUser.getPassword();
    }

    @Override
    public String getUsername() {
        return myUser.getUsername();
    }

    // we will skip this for now
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(()->"read");
    }

    // we will just return true for all the other boolean for now...
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}


```

```java

public interface MyUserRepository extends JpaRepository<MyUser, Integer> {

    // although there will be a name mapping, lets just add the query to it
    @Query("""
    SELECT u from MyUser u WHERE u.username = :username
    """)
    Optional<MyUser> findUserByUsername(String username);
}


```

```java

@Entity
@Table(name = "users")  // matching the one in the database
@Getter
@Setter
public class MyUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;
    private String password;
}


```

```java

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder thePasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}


```


---

Note

    - User
        - it has GrantedAuthorities
            - this can be 
                - AUTHORITIES  or
                - ROLES

    - there is nothing that is differentiating the Authorities and the roles -> it is conceptual
    - it is from one contract - GrantedAuthorities

    - From a conceptual point
        - Authorities : It is an action, that the user can do in your application
            - e.g. : Read, Write, Delete, Execute .... like basically to do something
        - Roles : It is sort of a badge
            - e.g. : Admin, Support, Sales, Client, Visitor ...


- End of lesson 2 code

```java

@RestController
public class DemoController {


    @GetMapping("/demo")
    public String demo(){

        var theAuthentication = SecurityContextHolder.getContext().getAuthentication();
        theAuthentication.getAuthorities().forEach(System.out::println);


        return "this is a demo app";
    }
}


```

```java

@Entity
@Getter
@Setter
@Table(name = "authorities")
public class MyAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private  int id;

    private  String name;

    // relationship
    @ManyToMany(mappedBy = "myAuthorities")
    private Set<MyUser> myUsers;
}


```

```java

@Entity
@Table(name = "users")  // matching the one in the database
@Getter
@Setter
public class MyUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "users_authorities",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id")
    )
    private Set<MyAuthority> myAuthorities;
}


```

```java

public interface MyUserRepository extends JpaRepository<MyUser, Integer> {

    // although there will be a name mapping, lets just add the query to it
    @Query("""
    SELECT u from MyUser u WHERE u.username = :username
    """)
    Optional<MyUser> findUserByUsername(String username);
}


```

```java

@AllArgsConstructor
public class MyGrantedAuthority implements GrantedAuthority {

    private final MyAuthority myAuthority;


    @Override
    public String getAuthority() {
        return myAuthority.getName();
    }
}


```

```java

@AllArgsConstructor
public class MyUserDetails implements UserDetails {

    private final MyUser myUser;

    @Override
    public String getPassword() {
        return myUser.getPassword();
    }

    @Override
    public String getUsername() {
        return myUser.getUsername();
    }



    // we will skip this for now
    /*
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(()->"read");
    }
    */

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return myUser
                .getMyAuthorities()
                .stream()
                .map(MyGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    // we will just return true for all the other boolean for now...
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}


```


```java

@AllArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {

    private final MyUserRepository myUserRepository;


    @Override
    public UserDetails loadUserByUsername(String username) {
        var myUser = myUserRepository.findUserByUsername(username);

        return myUser
                .map(MyUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found: " + username));

    }
}


```

```bash

spring.application.name=managingUsers

# mysql
spring.datasource.url=jdbc:mysql://localhost/ss_lesson2
spring.datasource.username=root
spring.datasource.password=***

```


## Lesson 3 - Custom Authentication

- Purely different authentication mechanism 

 - Flow
    - `http` -> goes to
        - Custom Authentication Filter ->
            - -> Custom Authentication Manager ->
                - -> Authentication Provider -> [UsernameAndPassword, PasswordEncoder]
---

-> What we want to do
 - The idea
     - We have a static key -> we want the `http` to use that static key to get authenticated
     - if the request has that key -> only then does it get authenticated

 - our custom Authentication for this lesson will only rely on `key`
    
```java

// previously, we extens the WebSecurityConfigurerAdapter
// so we define a bean of type SecurttyFilterChain



```

```java

// custom auth filter
    /*
     - when implementing the Filter from the javac.servlet.Filter
     - is it guaranteed that the filter will be called once?
     - if not do not implement the `Filter`
        - implement the `OncePerRequesrFiler`
    */


```

## Lesson 4 - Multiple Authentication providers

 - Say, you have multiple filters, each of them can have it own authentication that -> it passes to the authentication Manager -> then -> Authentication provider

 - easily be done with multiple custom filters or multiple default filters
 - difficult part is -> when you have a say, 1 custom filter, the rest are default filters : not very common

 - we will try and implement 1 custom filter, and I default filter

 // right from the HTTP request
    -> the custom filters will go to their own authentication manager -> own authentication  providers
    -> the default filters will do likewise

- What we will be doing
    - the application will allow for both HTTPbasic and API key

- lets dive in
    - we keep the application simple [no db, concentration is on configuaration]


// in the past, what we could have done is: 

 - created a `SecurityConfig` class and extended `WebSecurityConfigurerAdapter`

 // we donot do this anymore

// we use the `SecurityFilterChain`


```java

@Configuration
public class SecurityConfig {

    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        
    }
    
}

```

 - When the `httpBasic` is called it creates a configurer
  - when the application starts it creates the filter, authentication manager, then the authentication providers

Note

```java

// when creating your own authentication manager or authenticaion provider

http.httpBasic()
    // .and().authenticationManager() or by adding a bea of type AuthenticationManager
    // .and().authenticationProvider() //>> this does not overide the Authentication Provider, it adds one more to the collection

    .and().build()

```

 - Filter -> Manager -> Provider -> User details service (if needed)


 - We create the custom filter - `MyApiKeyFilter` -> extends -> `OncePerRequestFilter`
 - the authentication - `MyApiKeyAuthentication` -> implements -> `Authentication`
 - the authentication manager - `MyApiKeyAuthenticationManager` ->  implements -> `AuthenticationManager` 

 - apply `myApiKeyFilter` before `BasicAuthenticatioFilter`



 // note that
  - it creates the authenticaton manager builder
  - then it creates the authentication manager
  - then it goes into the filters




```java

package com.frankaboagye.springlesson4.config;


import com.frankaboagye.springlesson4.config.filters.MyApiKeyFilter;
import com.frankaboagye.springlesson4.config.managers.MyApiKeyAuthenticationManager;
import com.frankaboagye.springlesson4.config.providers.MyApiKeyProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final MyApiKeyFilter myApiKeyFilter;
    // private final MyApiKeyProvider myApiKeyProvider;
    // private final MyApiKeyAuthenticationManager myApiKeyAuthenticationManager;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity
                .authorizeHttpRequests(
                        authRequests -> {
                            authRequests.requestMatchers("/demo/public").permitAll();
                            authRequests.anyRequest().authenticated();
                        }
                )
                // .authenticationManager(myApiKeyAuthenticationManager)
                // .authenticationProvider(myApiKeyProvider)
                .addFilterBefore(myApiKeyFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }

}

/*]
return http.httpBasic(

                httpSecurityHttpBasicConfigurer -> {

                    try {
                        httpSecurityHttpBasicConfigurer.configure(
                                http
                                        .addFilterBefore(
                                                new MyApiKeyFilter(mySecretKey), BasicAuthenticationFilter.class
                                        )
                                        .authorizeHttpRequests(
                                                authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry.anyRequest().authenticated()
                                        )

                        );
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                }

        ).build();
 */
```


```java

package com.frankaboagye.springlesson4.config.providers;

import com.frankaboagye.springlesson4.config.authentications.MyApiKeyAuthentication;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@Component
public class MyApiKeyProvider implements AuthenticationProvider {


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        MyApiKeyAuthentication theAuthentication = (MyApiKeyAuthentication) authentication;  // we know the kind of authentication that is coming, so we can type cast it
        if("LLM".equals(theAuthentication.getKey())){
            theAuthentication.setAuthenticated(true);
            return theAuthentication;
        }else{
            throw new BadCredentialsException("Bad credentials: From KAF");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MyApiKeyAuthentication.class.equals(authentication);
    }
}



```


```java

package com.frankaboagye.springlesson4.config.managers;

import com.frankaboagye.springlesson4.config.providers.MyApiKeyProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@Component
public class MyApiKeyAuthenticationManager implements AuthenticationManager {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        MyApiKeyProvider myApiKeyProvider = new MyApiKeyProvider();

        if(myApiKeyProvider.supports(authentication.getClass())){
            return myApiKeyProvider.authenticate(authentication);
        }

        return authentication;


    }
}


````


```java

package com.frankaboagye.springlesson4.config.filters;

import com.frankaboagye.springlesson4.config.authentications.MyApiKeyAuthentication;
import com.frankaboagye.springlesson4.config.managers.MyApiKeyAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Service
@AllArgsConstructor
public class MyApiKeyFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        var requestKey = request.getHeader("x-api-key"); // that is the standard

        // if the requestKey is not there - proceed to use basic authentication - i.e. username and password
        // side note : spring boot: defaults :: ----- username: user     ----- password : <the generated password in the console> : try it with postman
        if(requestKey == null || requestKey.isEmpty() || requestKey.equals("null")){
            filterChain.doFilter(request, response);
        }

        MyApiKeyAuthentication theAuthenticationComingIn = new MyApiKeyAuthentication(requestKey, false);


        MyApiKeyAuthenticationManager manager = new MyApiKeyAuthenticationManager();

        try {

            var theAuthentication =  manager.authenticate(theAuthenticationComingIn);

            if(theAuthentication.isAuthenticated()){
                SecurityContextHolder.getContext().setAuthentication(theAuthentication);

            }else{
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }

        }catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        // continue
        filterChain.doFilter(request, response);

    }
}


```


```java

package com.frankaboagye.springlesson4.config.authentications;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;
import java.util.List;

@AllArgsConstructor
@Getter @Setter
public class MyApiKeyAuthentication implements Authentication {


    private final String key;

    private boolean authenticated;


    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    // leave the rest

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public String getName() {
        return "";
    }

    @Override
    public boolean implies(Subject subject) {
        return Authentication.super.implies(subject);
    }

}


```

 - in `applications.properties`

```java
MYSECRETKEY=THESECRET
``` 


