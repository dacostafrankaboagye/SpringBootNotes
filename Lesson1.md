
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

    - Filter which implements the 
      - Http Basic Authenticaton -> delegate to another object
        - Authentication Manager -> delegates to another object
            - Authentication Provider -> uses the "UserDetailsService" & "PasswordEncoder"


# Lesson 2 

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
