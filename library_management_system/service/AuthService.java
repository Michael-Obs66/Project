@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    private final Map<String, String> refreshTokens = new HashMap<>(); // ideally pakai DB/Redis

    public void registerUser(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists!");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("MEMBER");
        userRepository.save(user);
    }

    public AuthResponse authenticate(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        refreshTokens.put(user.getUsername(), refreshToken);

        return new AuthResponse(accessToken, refreshToken, "Bearer");
    }

    public AuthResponse refreshToken(String refreshToken) {
        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateRefreshToken(refreshToken) ||
                !refreshTokens.getOrDefault(username, "").equals(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccessToken = jwtUtil.generateAccessToken(user);
        return new AuthResponse(newAccessToken, refreshToken, "Bearer");
    }

    public void logout(String refreshToken) {
        String username = jwtUtil.extractUsername(refreshToken);
        refreshTokens.remove(username);
    }
}
