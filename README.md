# Spring Boot Cheat Sheet

A comprehensive reference for Spring Boot - a Java framework that simplifies Spring application development.

---

## Table of Contents
- [Setup and Configuration](#setup-and-configuration)
- [Annotations](#annotations)
- [Controllers](#controllers)
- [Data and JPA](#data-and-jpa)
- [Security](#security)
- [Testing](#testing)
- [Configuration Properties](#configuration-properties)
- [Profiles](#profiles)

---

## Setup and Configuration

### Maven Dependencies
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.1.0</version>
        <relativePath/>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>my-app</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <packaging>jar</packaging>
    
    <dependencies>
        <!-- Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- JPA -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        
        <!-- Security -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        
        <!-- Database -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
        
        <!-- Testing -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### Main Application Class
```java
@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}

// With custom configuration
@SpringBootApplication
@EnableJpaRepositories
@EnableScheduling
public class MyApplication {
    
    @Bean
    public CommandLineRunner demo(UserRepository repository) {
        return (args) -> {
            repository.save(new User("John", "john@example.com"));
        };
    }
    
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

## Annotations

### Core Annotations
```java
// Component scanning
@Component
@Service
@Repository
@Controller
@RestController
@Configuration

// Dependency injection
@Autowired
@Qualifier("specificBean")
@Value("${app.name}")

// Bean definition
@Bean
@Primary
@Scope("singleton")

// Conditional
@ConditionalOnProperty(name="feature.enabled", havingValue="true")
@ConditionalOnClass(DataSource.class)

// Configuration
@ConfigurationProperties(prefix="app")
@EnableConfigurationProperties(AppProperties.class)

// Profiles
@Profile("dev")
@ActiveProfiles("test")

// Validation
@Valid
@NotNull
@Size(min=2, max=30)
@Email
```

## Controllers

### REST Controllers
```java
@RestController
@RequestMapping("/api/posts")
@Validated
public class PostController {
    
    @Autowired
    private PostService postService;
    
    // GET all posts
    @GetMapping
    public ResponseEntity<Page<Post>> getAllPosts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<Post> posts = postService.findAll(search, pageable);
        return ResponseEntity.ok(posts);
    }
    
    // GET single post
    @GetMapping("/{id}")
    public ResponseEntity<Post> getPost(@PathVariable Long id) {
        Post post = postService.findById(id);
        return ResponseEntity.ok(post);
    }
    
    // CREATE post
    @PostMapping
    public ResponseEntity<Post> createPost(@Valid @RequestBody CreatePostRequest request) {
        Post post = postService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(post);
    }
    
    // UPDATE post
    @PutMapping("/{id}")
    public ResponseEntity<Post> updatePost(
            @PathVariable Long id, 
            @Valid @RequestBody UpdatePostRequest request) {
        Post post = postService.update(id, request);
        return ResponseEntity.ok(post);
    }
    
    // DELETE post
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePost(@PathVariable Long id) {
        postService.delete(id);
        return ResponseEntity.noContent().build();
    }
    
    // Exception handling
    @ExceptionHandler(PostNotFoundException.class)
    public ResponseEntity<ErrorResponse> handlePostNotFound(PostNotFoundException ex) {
        ErrorResponse error = new ErrorResponse("POST_NOT_FOUND", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }
}

// Request/Response DTOs
public class CreatePostRequest {
    @NotBlank(message = "Title is required")
    @Size(max = 100)
    private String title;
    
    @NotBlank(message = "Content is required")
    private String content;
    
    // getters and setters
}

@Data
@AllArgsConstructor
public class ErrorResponse {
    private String code;
    private String message;
}
```

## Data and JPA

### Entity Classes
```java
@Entity
@Table(name = "posts")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Post {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 100)
    private String title;
    
    @Column(columnDefinition = "TEXT")
    private String content;
    
    @CreationTimestamp
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
    
    @OneToMany(mappedBy = "post", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Comment> comments = new ArrayList<>();
    
    @ManyToMany
    @JoinTable(
        name = "post_tags",
        joinColumns = @JoinColumn(name = "post_id"),
        inverseJoinColumns = @JoinColumn(name = "tag_id")
    )
    private Set<Tag> tags = new HashSet<>();
}

@Entity
@Table(name = "users")
@Data
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    @Email
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    @Enumerated(EnumType.STRING)
    private UserRole role;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Post> posts = new ArrayList<>();
}
```

### Repository Interfaces
```java
@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    
    // Query methods
    List<Post> findByTitleContainingIgnoreCase(String title);
    List<Post> findByUser(User user);
    List<Post> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);
    
    @Query("SELECT p FROM Post p WHERE p.title LIKE %:keyword% OR p.content LIKE %:keyword%")
    Page<Post> searchPosts(@Param("keyword") String keyword, Pageable pageable);
    
    @Query(value = "SELECT * FROM posts WHERE published = true ORDER BY created_at DESC", 
           nativeQuery = true)
    List<Post> findPublishedPosts();
    
    @Modifying
    @Query("UPDATE Post p SET p.title = :title WHERE p.id = :id")
    int updatePostTitle(@Param("id") Long id, @Param("title") String title);
    
    // Custom query with pagination
    @Query("SELECT p FROM Post p JOIN p.tags t WHERE t.name = :tagName")
    Page<Post> findByTagName(@Param("tagName") String tagName, Pageable pageable);
}

// Custom repository implementation
@Component
public class CustomPostRepositoryImpl implements CustomPostRepository {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    @Override
    public List<Post> findPostsWithCustomLogic(String criteria) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Post> query = cb.createQuery(Post.class);
        Root<Post> root = query.from(Post.class);
        
        // Add custom criteria
        query.select(root).where(cb.like(root.get("title"), "%" + criteria + "%"));
        
        return entityManager.createQuery(query).getResultList();
    }
}
```

### Service Layer
```java
@Service
@Transactional
public class PostService {
    
    @Autowired
    private PostRepository postRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Transactional(readOnly = true)
    public Page<Post> findAll(String search, Pageable pageable) {
        if (search != null && !search.isEmpty()) {
            return postRepository.searchPosts(search, pageable);
        }
        return postRepository.findAll(pageable);
    }
    
    @Transactional(readOnly = true)
    public Post findById(Long id) {
        return postRepository.findById(id)
            .orElseThrow(() -> new PostNotFoundException("Post not found with id: " + id));
    }
    
    public Post create(CreatePostRequest request) {
        User user = getCurrentUser();
        
        Post post = new Post();
        post.setTitle(request.getTitle());
        post.setContent(request.getContent());
        post.setUser(user);
        
        return postRepository.save(post);
    }
    
    public Post update(Long id, UpdatePostRequest request) {
        Post post = findById(id);
        
        // Check ownership
        if (!post.getUser().equals(getCurrentUser())) {
            throw new AccessDeniedException("You don't have permission to update this post");
        }
        
        post.setTitle(request.getTitle());
        post.setContent(request.getContent());
        
        return postRepository.save(post);
    }
    
    public void delete(Long id) {
        Post post = findById(id);
        
        if (!post.getUser().equals(getCurrentUser())) {
            throw new AccessDeniedException("You don't have permission to delete this post");
        }
        
        postRepository.delete(post);
    }
    
    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = auth.getName();
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
```

## Security

### Security Configuration
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/posts/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/dashboard")
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .permitAll()
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            );
        
        return http.build();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}

// User details service
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        
        return UserPrincipal.create(user);
    }
}

// JWT Configuration (if using JWT)
@Component
public class JwtTokenProvider {
    
    @Value("${app.jwtSecret}")
    private String jwtSecret;
    
    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;
    
    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);
        
        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
```

## Testing

### Unit Tests
```java
@ExtendWith(MockitoExtension.class)
class PostServiceTest {
    
    @Mock
    private PostRepository postRepository;
    
    @Mock
    private UserRepository userRepository;
    
    @InjectMocks
    private PostService postService;
    
    @Test
    void shouldCreatePost() {
        // Given
        CreatePostRequest request = new CreatePostRequest("Title", "Content");
        User user = new User();
        user.setId(1L);
        
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(postRepository.save(any(Post.class))).thenAnswer(i -> i.getArgument(0));
        
        // When
        Post result = postService.create(request);
        
        // Then
        assertThat(result.getTitle()).isEqualTo("Title");
        assertThat(result.getUser()).isEqualTo(user);
        verify(postRepository).save(any(Post.class));
    }
    
    @Test
    void shouldThrowExceptionWhenPostNotFound() {
        // Given
        when(postRepository.findById(1L)).thenReturn(Optional.empty());
        
        // When & Then
        assertThrows(PostNotFoundException.class, () -> postService.findById(1L));
    }
}

// Integration tests
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class PostRepositoryIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:13")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");
    
    @Autowired
    private TestEntityManager entityManager;
    
    @Autowired
    private PostRepository postRepository;
    
    @Test
    void shouldFindPostsByTitle() {
        // Given
        User user = new User();
        user.setEmail("test@example.com");
        entityManager.persist(user);
        
        Post post = new Post();
        post.setTitle("Spring Boot Test");
        post.setContent("Content");
        post.setUser(user);
        entityManager.persist(post);
        
        entityManager.flush();
        
        // When
        List<Post> found = postRepository.findByTitleContainingIgnoreCase("spring");
        
        // Then
        assertThat(found).hasSize(1);
        assertThat(found.get(0).getTitle()).isEqualTo("Spring Boot Test");
    }
}

// Web layer tests
@WebMvcTest(PostController.class)
class PostControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private PostService postService;
    
    @Test
    @WithMockUser
    void shouldReturnPosts() throws Exception {
        // Given
        Page<Post> posts = new PageImpl<>(Collections.emptyList());
        when(postService.findAll(any(), any())).thenReturn(posts);
        
        // When & Then
        mockMvc.perform(get("/api/posts"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }
    
    @Test
    @WithMockUser
    void shouldCreatePost() throws Exception {
        // Given
        CreatePostRequest request = new CreatePostRequest("Title", "Content");
        Post post = new Post();
        post.setId(1L);
        post.setTitle("Title");
        
        when(postService.create(any())).thenReturn(post);
        
        // When & Then
        mockMvc.perform(post("/api/posts")
                .contentType(MediaType.APPLICATION_JSON)
                .content(asJsonString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value("Title"));
    }
}
```

## Configuration Properties

### Application Properties
```yaml
# application.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mydb
    username: user
    password: password
    driver-class-name: com.mysql.cj.jdbc.Driver
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.MySQL8Dialect
  
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}

server:
  port: 8080
  servlet:
    context-path: /api

logging:
  level:
    com.example: DEBUG
    org.springframework.security: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"

app:
  jwt-secret: mySecret
  jwt-expiration-ms: 86400000
```

### Custom Properties
```java
@ConfigurationProperties(prefix = "app")
@Data
public class AppProperties {
    private String jwtSecret;
    private int jwtExpirationMs;
    private Upload upload = new Upload();
    
    @Data
    public static class Upload {
        private String path;
        private long maxFileSize;
    }
}

// Enable in main class
@EnableConfigurationProperties({AppProperties.class})
@SpringBootApplication
public class MyApplication {
    // ...
}

// Usage
@Service
public class FileService {
    
    @Autowired
    private AppProperties appProperties;
    
    public void uploadFile(MultipartFile file) {
        String uploadPath = appProperties.getUpload().getPath();
        // ...
    }
}
```

## Profiles

### Profile-specific Configuration
```yaml
# application.yml (default)
spring:
  profiles:
    active: dev

---
# application-dev.yml
spring:
  config:
    activate:
      on-profile: dev
  datasource:
    url: jdbc:h2:mem:devdb
  h2:
    console:
      enabled: true

---
# application-prod.yml
spring:
  config:
    activate:
      on-profile: prod
  datasource:
    url: jdbc:mysql://prod-server:3306/proddb
```

```java
@Configuration
@Profile("dev")
public class DevConfig {
    
    @Bean
    @Primary
    public EmailService mockEmailService() {
        return new MockEmailService();
    }
}

@Configuration
@Profile("prod")
public class ProdConfig {
    
    @Bean
    public EmailService realEmailService() {
        return new SmtpEmailService();
    }
}
```

---

## Common Patterns

| Pattern | Use Case | Implementation |
|---------|----------|----------------|
| Repository Pattern | Data access layer | `@Repository` interfaces |
| Service Layer | Business logic | `@Service` classes |
| DTO Pattern | Data transfer | Request/Response classes |
| Factory Pattern | Bean creation | `@Configuration` + `@Bean` |

---

## Resources
- [Official Spring Boot Documentation](https://spring.io/projects/spring-boot)
- [Spring Boot Reference Guide](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/)
- [Spring Framework Documentation](https://spring.io/projects/spring-framework)
- [Baeldung Spring Tutorials](https://www.baeldung.com/spring-boot)

---
*Originally compiled from various sources. Contributions welcome!*