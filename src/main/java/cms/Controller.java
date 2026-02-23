package cms;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.Date;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class Controller {

    private final JdbcTemplate jdbc;

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    // token -> session
    private final Map<String, Session> sessions = new HashMap<>();

    public Controller(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // =========================
    // Models
    // =========================
    static class Session {
        public int userId;
        public String username;
        public String role;
        public boolean firstLogin;
        public Session(int userId, String username, String role, boolean firstLogin) {
            this.userId = userId;
            this.username = username;
            this.role = role;
            this.firstLogin = firstLogin;
        }
    }

    static class LoginReq { public String username; public String password; }
    static class CreateUserReq { public String username; public String password; public String role; }

    static class UserDetailsReq {
        public Integer user_id;
        public String name;
        public String address;
        public String phone;
        public String email;
        public String branch;
        public String gender;
        public String dob; // yyyy-MM-dd or MM/dd/yyyy
    }

    static class ChangePasswordReq {
        public String oldPassword;
        public String newPassword;
    }

    // =========================
    // ✅ TOKEN MODELS (ADDED)
    // =========================
    static class TokenReq {
        public String username;
        public String problem;
    }

    static class AdminProfileUpdateReq {
        public String username;
        public String name;
        public String address;
        public String phone;
        public String email;
        public String branch;
        public String gender;
        public String dob; // yyyy-MM-dd or MM/dd/yyyy
    }

    // =========================
    // Helpers
    // =========================
    private ResponseEntity<?> unauthorized(String msg) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", msg));
    }

    private ResponseEntity<?> forbidden(String msg) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", msg));
    }

    private Session requireSession(String token) {
        if (token == null || token.isBlank()) return null;
        return sessions.get(token);
    }

    private boolean isAdmin(Session s) {
        return s != null && "admin".equalsIgnoreCase(s.role);
    }

    private LocalDate parseDateFlexible(String s) {
        if (s == null) throw new IllegalArgumentException("date required");
        s = s.trim();

        List<DateTimeFormatter> fmts = List.of(
                DateTimeFormatter.ISO_LOCAL_DATE,            // 2026-02-16
                DateTimeFormatter.ofPattern("MM/dd/yyyy")    // 02/16/2026
        );

        for (DateTimeFormatter f : fmts) {
            try { return LocalDate.parse(s, f); }
            catch (DateTimeParseException ignored) {}
        }
        throw new IllegalArgumentException("Invalid date format: " + s);
    }

    private String saveFile(MultipartFile file, String subFolder) throws IOException {
        if (file == null || file.isEmpty()) return "";

        String original = StringUtils.cleanPath(Objects.requireNonNullElse(file.getOriginalFilename(), "file"));
        String ext = "";
        int dot = original.lastIndexOf('.');
        if (dot >= 0) ext = original.substring(dot);

        String safeName = UUID.randomUUID() + ext;

        Path base = Paths.get(uploadDir).toAbsolutePath().normalize();
        Path folder = base.resolve(subFolder).normalize();
        Files.createDirectories(folder);

        Path dest = folder.resolve(safeName);
        Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);

        return "/uploads/" + subFolder + "/" + safeName;
    }

    private String saveFilesJoin(MultipartFile[] files, String subFolder) throws IOException {
        if (files == null || files.length == 0) return "";
        StringBuilder sb = new StringBuilder();

        for (MultipartFile f : files) {
            if (f == null || f.isEmpty()) continue;
            String url = saveFile(f, subFolder);
            if (!url.isBlank()) {
                if (!sb.isEmpty()) sb.append("\n");
                sb.append(url);
            }
        }
        return sb.toString();
    }

    // ✅ ADDED: get userId by username
    private Integer findUserIdByUsername(String username) {
        if (username == null || username.isBlank()) return null;
        List<Integer> ids = jdbc.query(
                "SELECT id FROM users WHERE username=? LIMIT 1",
                new Object[]{ username.trim() },
                (rs, i) -> rs.getInt("id")
        );
        if (ids.isEmpty()) return null;
        return ids.get(0);
    }

    // =========================
    // 1) LOGIN (JSON) ✅ now returns username also
    // =========================
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        if (req == null || req.username == null || req.password == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "username/password required"));
        }

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, username, role, first_login FROM users WHERE username=? AND password=?",
                req.username.trim(), req.password
        );

        if (rows.isEmpty()) return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));

        Map<String, Object> r = rows.get(0);
        int userId = ((Number) r.get("id")).intValue();
        String role = String.valueOf(r.get("role"));

        boolean firstLogin = Boolean.TRUE.equals(r.get("first_login")) ||
                (r.get("first_login") instanceof Number && ((Number) r.get("first_login")).intValue() == 1);

        String token = UUID.randomUUID().toString();
        sessions.put(token, new Session(userId, req.username.trim(), role, firstLogin));

        return ResponseEntity.ok(Map.of(
                "token", token,
                "role", role,
                "userId", userId,
                "firstLogin", firstLogin,
                "username", req.username.trim()
        ));
    }

    // =========================
    // 2) ADMIN: CREATE USER (JSON)
    // =========================
    @PostMapping("/admin/user")
    public ResponseEntity<?> createUser(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestBody CreateUserReq req
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        if (req == null || req.username == null || req.password == null || req.role == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "username/password/role required"));
        }

        String role = req.role.trim().toLowerCase();
        if (!role.equals("admin") && !role.equals("user")) {
            return ResponseEntity.badRequest().body(Map.of("error", "role must be admin or user"));
        }

        boolean firstLogin = role.equals("user");

        jdbc.update("INSERT INTO users(username,password,role,first_login) VALUES (?,?,?,?)",
                req.username.trim(), req.password, role, firstLogin);

        return ResponseEntity.ok(Map.of("message", "User created"));
    }

    // =========================
    // 3) ADMIN: ADD EVENT (MULTIPART)
    // =========================
    @PostMapping(value = "/admin/event", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> addEventMultipart(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestParam("title") String title,
            @RequestParam("event_date") String eventDate,
            @RequestParam(value = "registration_link", required = false) String registrationLink,
            @RequestPart(value = "photo", required = false) MultipartFile photo
    ) throws IOException {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        LocalDate d = parseDateFlexible(eventDate);
        String photoUrl = saveFile(photo, "event_photos");

        jdbc.update(
                "INSERT INTO upcoming_events(title,event_date,photo_url,registration_link) VALUES (?,?,?,?)",
                title.trim(), Date.valueOf(d),
                photoUrl,
                registrationLink == null ? "" : registrationLink.trim()
        );

        return ResponseEntity.ok(Map.of("message", "Event saved", "photo_url", photoUrl));
    }

    // =========================
    // 4) ADMIN: ADD CONTENT (MULTIPART)
    // =========================
    @PostMapping(value = "/admin/content", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> addContentMultipart(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestParam("event_title") String eventTitle,
            @RequestParam("event_date") String eventDate,
            @RequestParam(value = "description", required = false) String description,
            @RequestParam(value = "youtube_links", required = false) String youtubeLinks,
            @RequestPart(value = "photos", required = false) MultipartFile[] photos,
            @RequestPart(value = "report", required = false) MultipartFile report
    ) throws IOException {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        LocalDate d = parseDateFlexible(eventDate);

        String photosText = saveFilesJoin(photos, "content_photos");
        String reportUrl = saveFile(report, "reports");

        jdbc.update(
                "INSERT INTO event_content(event_title,event_date,description,photos,youtube_links,report) VALUES (?,?,?,?,?,?)",
                eventTitle.trim(), Date.valueOf(d),
                description == null ? "" : description,
                photosText,
                youtubeLinks == null ? "" : youtubeLinks,
                reportUrl
        );

        return ResponseEntity.ok(Map.of("message", "Content saved", "report", reportUrl, "photos", photosText));
    }

    // =========================
    // ✅ ADMIN: MANAGE UPCOMING EVENTS (LIST)
    // =========================
    @GetMapping("/admin/events")
    public ResponseEntity<?> adminListEvents(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, title, DATE_FORMAT(event_date,'%Y-%m-%d') AS event_date, photo_url, registration_link " +
                        "FROM upcoming_events ORDER BY event_date ASC"
        );
        return ResponseEntity.ok(rows);
    }

    // ✅ ADMIN: DELETE UPCOMING EVENT
    @DeleteMapping("/admin/events/{id}")
    public ResponseEntity<?> adminDeleteEvent(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @PathVariable int id
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        int n = jdbc.update("DELETE FROM upcoming_events WHERE id=?", id);
        return ResponseEntity.ok(Map.of("deleted", n));
    }

    // ✅ ADMIN: MANAGE CONTENT (LIST)
    @GetMapping("/admin/contents")
    public ResponseEntity<?> adminListContents(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, event_title, DATE_FORMAT(event_date,'%Y-%m-%d') AS event_date, report, created_at " +
                        "FROM event_content ORDER BY event_date DESC, id DESC"
        );
        return ResponseEntity.ok(rows);
    }

    // ✅ ADMIN: DELETE CONTENT
    @DeleteMapping("/admin/contents/{id}")
    public ResponseEntity<?> adminDeleteContent(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @PathVariable int id
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        int n = jdbc.update("DELETE FROM event_content WHERE id=?", id);
        return ResponseEntity.ok(Map.of("deleted", n));
    }

    // =========================
    // 5) USER: SAVE DETAILS (JSON)
    // =========================
    @PostMapping("/user/details")
    public ResponseEntity<?> saveDetails(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestBody UserDetailsReq req
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");

        if (req == null || req.user_id == null) return ResponseEntity.badRequest().body(Map.of("error", "user_id required"));
        if (!Objects.equals(req.user_id, s.userId)) return forbidden("Cannot update another user");

        Date dob = null;
        if (req.dob != null && !req.dob.isBlank()) dob = Date.valueOf(parseDateFlexible(req.dob));

        jdbc.update(
                "INSERT INTO user_details(user_id,name,address,phone,email,branch,gender,dob) " +
                        "VALUES (?,?,?,?,?,?,?,?) " +
                        "ON DUPLICATE KEY UPDATE name=?, address=?, phone=?, email=?, branch=?, gender=?, dob=?",
                req.user_id, req.name, req.address, req.phone, req.email, req.branch, req.gender, dob,
                req.name, req.address, req.phone, req.email, req.branch, req.gender, dob
        );

        jdbc.update("UPDATE users SET first_login=false WHERE id=?", req.user_id);
        s.firstLogin = false;

        return ResponseEntity.ok(Map.of("message", "Profile saved"));
    }

    // =========================
    // 6) USER: GET PROFILE
    // =========================
    @GetMapping("/user/profile")
    public ResponseEntity<?> getProfile(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestParam("userId") int userId
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (userId != s.userId) return forbidden("Cannot view another user");

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT name,address,phone,email,branch,gender,DATE_FORMAT(dob,'%Y-%m-%d') AS dob FROM user_details WHERE user_id=?",
                userId
        );

        if (rows.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "name","", "address","", "phone","", "email","", "branch","", "gender","", "dob",""
            ));
        }
        return ResponseEntity.ok(rows.get(0));
    }

    // =========================
    // ✅ USER: CHANGE PASSWORD (JSON)
    // =========================
    @PostMapping("/user/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestBody ChangePasswordReq req
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");

        if (req == null || req.oldPassword == null || req.newPassword == null ||
                req.oldPassword.isBlank() || req.newPassword.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "oldPassword/newPassword required"));
        }

        Integer cnt = jdbc.queryForObject(
                "SELECT COUNT(*) FROM users WHERE id=? AND password=?",
                Integer.class,
                s.userId, req.oldPassword
        );

        if (cnt == null || cnt == 0) {
            return ResponseEntity.status(400).body(Map.of("error", "Old password is wrong"));
        }

        jdbc.update("UPDATE users SET password=? WHERE id=?", req.newPassword, s.userId);
        return ResponseEntity.ok(Map.of("message", "Password changed"));
    }

    // =========================
    // 7) EVENTS (GET)
    // =========================
    @GetMapping("/events")
    public ResponseEntity<?> getEvents() {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT title, DATE_FORMAT(event_date, '%Y-%m-%d') AS event_date, photo_url, registration_link " +
                        "FROM upcoming_events ORDER BY event_date ASC"
        );
        return ResponseEntity.ok(rows);
    }

    // =========================
    // 8) CONTENT APIs (GET)
    // =========================
    @GetMapping("/content/titles")
    public ResponseEntity<?> getContentTitles() {
        List<String> titles = jdbc.query(
                "SELECT DISTINCT event_title FROM event_content ORDER BY event_title ASC",
                (rs, i) -> rs.getString("event_title")
        );
        return ResponseEntity.ok(titles);
    }

    @GetMapping("/content/dates")
    public ResponseEntity<?> getContentDates(@RequestParam("title") String title) {
        List<String> dates = jdbc.query(
                "SELECT DATE_FORMAT(event_date, '%Y-%m-%d') AS d FROM event_content WHERE event_title=? ORDER BY event_date DESC",
                new Object[]{ title },
                (rs, i) -> rs.getString("d")
        );
        return ResponseEntity.ok(dates);
    }

    @GetMapping("/content")
    public ResponseEntity<?> getContent(@RequestParam("title") String title, @RequestParam("date") String date) {
        LocalDate d = parseDateFlexible(date);

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT description, photos, youtube_links, report FROM event_content WHERE event_title=? AND event_date=? LIMIT 1",
                title, Date.valueOf(d)
        );

        if (rows.isEmpty()) return ResponseEntity.status(404).body(Map.of("error", "No content found"));
        return ResponseEntity.ok(rows.get(0));
    }

    // ==========================================================
    // ✅ TOKEN FEATURE ENDPOINTS (ADDED)
    // ==========================================================

    // USER: Submit token (username + problem)
    @PostMapping("/user/token")
    public ResponseEntity<?> submitToken(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestBody TokenReq req
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");

        if (req == null || req.username == null || req.problem == null ||
                req.username.isBlank() || req.problem.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "username/problem required"));
        }

        // ✅ security: user can submit token only for own username
        if (!req.username.trim().equalsIgnoreCase(s.username)) {
            return forbidden("You can submit token only for your own username");
        }

        jdbc.update(
                "INSERT INTO token_requests(user_id, username, problem, created_at) VALUES (?,?,?,NOW())",
                s.userId, s.username, req.problem.trim()
        );

        return ResponseEntity.ok(Map.of("message", "Token submitted"));
    }

    // ADMIN: List tokens
    @GetMapping("/admin/tokens")
    public ResponseEntity<?> adminListTokens(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, username, problem, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i') AS created_at " +
                        "FROM token_requests ORDER BY id DESC"
        );
        return ResponseEntity.ok(rows);
    }

    // ADMIN: Get profile by username (for correction)
    @GetMapping("/admin/profile")
    public ResponseEntity<?> adminGetProfileByUsername(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestParam("username") String username
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        Integer userId = findUserIdByUsername(username);
        if (userId == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT name,address,phone,email,branch,gender,DATE_FORMAT(dob,'%Y-%m-%d') AS dob " +
                        "FROM user_details WHERE user_id=?",
                userId
        );

        if (rows.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "username", username.trim(),
                    "user_id", userId,
                    "name","", "address","", "phone","", "email","", "branch","", "gender","", "dob",""
            ));
        }

        Map<String, Object> out = new HashMap<>(rows.get(0));
        out.put("username", username.trim());
        out.put("user_id", userId);
        return ResponseEntity.ok(out);
    }

    // ADMIN: Update profile by username
    @PostMapping("/admin/profile/update")
    public ResponseEntity<?> adminUpdateProfile(
            @RequestHeader(value = "X-Auth-Token", required = false) String token,
            @RequestBody AdminProfileUpdateReq req
    ) {
        Session s = requireSession(token);
        if (s == null) return unauthorized("Missing/invalid token");
        if (!isAdmin(s)) return forbidden("Admin only");

        if (req == null || req.username == null || req.username.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "username required"));
        }

        Integer userId = findUserIdByUsername(req.username);
        if (userId == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        Date dob = null;
        if (req.dob != null && !req.dob.isBlank()) {
            dob = Date.valueOf(parseDateFlexible(req.dob));
        }

        jdbc.update(
                "INSERT INTO user_details(user_id,name,address,phone,email,branch,gender,dob) " +
                        "VALUES (?,?,?,?,?,?,?,?) " +
                        "ON DUPLICATE KEY UPDATE name=?, address=?, phone=?, email=?, branch=?, gender=?, dob=?",
                userId,
                req.name == null ? "" : req.name,
                req.address == null ? "" : req.address,
                req.phone == null ? "" : req.phone,
                req.email == null ? "" : req.email,
                req.branch == null ? "" : req.branch,
                req.gender == null ? "" : req.gender,
                dob,
                req.name == null ? "" : req.name,
                req.address == null ? "" : req.address,
                req.phone == null ? "" : req.phone,
                req.email == null ? "" : req.email,
                req.branch == null ? "" : req.branch,
                req.gender == null ? "" : req.gender,
                dob
        );

        return ResponseEntity.ok(Map.of("message", "Profile updated"));
    }
}