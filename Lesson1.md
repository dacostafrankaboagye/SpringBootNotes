
# Lesson 1

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

    - Filter with Imolements the 
      - Http Basic Authenticaton -> delegate to another object
        - Authentication Manager -> delegates to another object
            - Authentication Provider -> uses the "UserDetailsService" & "PasswordEncoder"

