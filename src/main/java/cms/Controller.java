package cms;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MultipartFile;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import jakarta.transaction.Transactional;

/**
 * Controller.java (SINGLE FILE)
 *
 * ✅ Fixes: "Transaction silently rolled back because it has been marked as rollback-only"
 *    - NO try/catch inside @Transactional endpoints
 *    - Global exception handler (@RestControllerAdvice)
 *    - OTP insert runs in its own transaction (REQUIRES_NEW) via OtpService
 *    - Email send happens OUTSIDE the DB transaction
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class Controller {

    // ===================== FILE UPLOAD =====================
    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    // ===================== DB =====================
    @PersistenceContext
    private EntityManager em;

    // ===================== MAIL =====================
    private final JavaMailSender mailSender;

    // ===================== OTP SERVICE (TX SAFE) =====================
    private final OtpService otpService;

    public Controller(JavaMailSender mailSender, OtpService otpService) {
        this.mailSender = mailSender;
        this.otpService = otpService;
    }

    // ===================== AUTH TOKEN STORE (IN-MEMORY) =====================
    private final Map<String, String> tokenToUser = new ConcurrentHashMap<>();
    private final Map<String, String> tokenToRole = new ConcurrentHashMap<>();

    private final SecureRandom random = new SecureRandom();

    // ===================== RESPONSE HELPERS =====================
    private Map<String, Object> ok() {
        return new LinkedHashMap<>(Map.of("ok", true));
    }

    private Map<String, Object> ok(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return m;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }

    // ===================== AUTH HELPERS =====================
    private String requireTokenUser(String token) {
        if (!notBlank(token)) throw new RuntimeException("Missing token");
        String u = tokenToUser.get(token);
        if (!notBlank(u)) throw new RuntimeException("Invalid session. Login again.");
        return u;
    }

    private String requireTokenRole(String token) {
        if (!notBlank(token)) throw new RuntimeException("Missing token");
        String r = tokenToRole.get(token);
        if (!notBlank(r)) throw new RuntimeException("Invalid session. Login again.");
        return r;
    }

    private void requireAdmin(String token) {
        String role = requireTokenRole(token);
        if (!"admin".equalsIgnoreCase(role)) throw new RuntimeException("Admin only");
    }

    private String newToken() {
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
    }

    // ===================== DB HELPERS: USERS =====================
    private boolean userExists(String username) {
        Query q = em.createNativeQuery("SELECT COUNT(*) FROM users WHERE username=?");
        q.setParameter(1, username);
        Number n = (Number) q.getSingleResult();
        return n.longValue() > 0;
    }

    private Long userIdOf(String username) {
        Query q = em.createNativeQuery("SELECT id FROM users WHERE username=?");
        q.setParameter(1, username);
        List<?> rows = q.getResultList();
        if (rows.isEmpty()) return null;
        return ((Number) rows.get(0)).longValue();
    }

    @Transactional
    private void createUserInternal(String username, String password, String role) {
        em.createNativeQuery("INSERT INTO users(username,password,role) VALUES (?,?,?)")
                .setParameter(1, username)
                .setParameter(2, password)
                .setParameter(3, role)
                .executeUpdate();
    }

    private Map<String, Object> getUserRow(String username) {
        Query q = em.createNativeQuery("SELECT id, username, password, role FROM users WHERE username=?");
        q.setParameter(1, username);
        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) return null;
        Object[] r = rows.get(0);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", ((Number) r[0]).longValue());
        m.put("username", String.valueOf(r[1]));
        m.put("password", String.valueOf(r[2]));
        m.put("role", String.valueOf(r[3]));
        return m;
    }

    private Map<String, Object> getProfileRowByUserId(Long userId) {
        Query q = em.createNativeQuery("""
            SELECT name, phone, email, branch, gender, dob, address
            FROM user_profiles WHERE user_id=?
        """);
        q.setParameter(1, userId);
        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) return null;

        Object[] r = rows.get(0);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", r[0] == null ? "" : String.valueOf(r[0]));
        m.put("phone", r[1] == null ? "" : String.valueOf(r[1]));
        m.put("email", r[2] == null ? "" : String.valueOf(r[2]));
        m.put("branch", r[3] == null ? "" : String.valueOf(r[3]));
        m.put("gender", r[4] == null ? "" : String.valueOf(r[4]));
        m.put("dob", r[5] == null ? "" : String.valueOf(r[5]));
        m.put("address", r[6] == null ? "" : String.valueOf(r[6]));
        return m;
    }

    private boolean isProfileComplete(Map<String, Object> p) {
        if (p == null) return false;
        return notBlank(String.valueOf(p.getOrDefault("name", "")))
                && notBlank(String.valueOf(p.getOrDefault("address", "")))
                && notBlank(String.valueOf(p.getOrDefault("phone", "")))
                && notBlank(String.valueOf(p.getOrDefault("email", "")))
                && notBlank(String.valueOf(p.getOrDefault("branch", "")))
                && notBlank(String.valueOf(p.getOrDefault("gender", "")))
                && notBlank(String.valueOf(p.getOrDefault("dob", "")));
    }

    // ===================== FILE HELPERS =====================
    private String saveUpload(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) return null;

        Files.createDirectories(Paths.get(uploadDir));

        String original = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
        String ext = "";
        int idx = original.lastIndexOf('.');
        if (idx >= 0) ext = original.substring(idx);

        String name = UUID.randomUUID().toString().replace("-", "") + ext;
        Path dest = Paths.get(uploadDir).resolve(name).normalize();
        Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);
        return "/uploads/" + name;
    }

    // ===================== OTP HELPERS =====================
    private String genOtp6() {
        int v = 100000 + random.nextInt(900000);
        return String.valueOf(v);
    }

    private void sendOtpMail(String to, String subject, String body) {
        if (mailSender == null) throw new RuntimeException("MailSender not configured.");
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(body);
        mailSender.send(msg);
    }

    private String getEmailForUser(String username) {
        Long uid = userIdOf(username);
        if (uid == null) return null;
        Map<String, Object> p = getProfileRowByUserId(uid);
        if (p == null) return null;
        String email = String.valueOf(p.getOrDefault("email", "")).trim();
        return notBlank(email) ? email : null;
    }

    // ===================== LOGIN =====================
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, Object> body) {
        String username = String.valueOf(body.getOrDefault("username", "")).trim();
        String password = String.valueOf(body.getOrDefault("password", ""));

        if (!notBlank(username) || !notBlank(password)) {
            throw new RuntimeException("username/password required");
        }

        Map<String, Object> u = getUserRow(username);
        if (u == null) throw new RuntimeException("Invalid username/password");

        String pw = String.valueOf(u.get("password"));
        if (!Objects.equals(pw, password)) throw new RuntimeException("Invalid username/password");

        Long uid = ((Number) u.get("id")).longValue();
        Map<String, Object> p = getProfileRowByUserId(uid);
        boolean complete = isProfileComplete(p);

        String token = newToken();
        tokenToUser.put(token, username);
        tokenToRole.put(token, String.valueOf(u.get("role")));

        return ResponseEntity.ok(ok(
                "token", token,
                "username", username,
                "role", u.get("role"),
                "profileComplete", complete
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        if (notBlank(token)) {
            tokenToUser.remove(token);
            tokenToRole.remove(token);
        }
        return ResponseEntity.ok(ok());
    }

// ===================== CLUBS =====================
@GetMapping("/clubs")
public ResponseEntity<?> clubs() {
    Query q = em.createNativeQuery("SELECT club_name FROM clubs ORDER BY club_name ASC");
    List<?> rows = q.getResultList();
    List<String> items = new ArrayList<>();
    for (Object r : rows) items.add(String.valueOf(r));
    return ResponseEntity.ok(ok("items", items));
}

@PostMapping("/clubs")
@Transactional
public ResponseEntity<?> addClub(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                 @RequestBody Map<String, Object> body) {
    requireAdmin(token);

    String name = String.valueOf(body.getOrDefault("name", "")).trim();
    String password = String.valueOf(body.getOrDefault("password", "")).trim(); // ✅ read password

    if (!notBlank(name)) throw new RuntimeException("Club name required");
    if (!notBlank(password)) throw new RuntimeException("Club password required"); // ✅ required

    em.createNativeQuery("INSERT INTO clubs(club_name, club_password) VALUES (?, ?)")
            .setParameter(1, name)
            .setParameter(2, password)   // ✅ THIS WAS MISSING
            .executeUpdate();

    em.createNativeQuery("""
        INSERT INTO recruitments(club, is_open, link)
        VALUES (?, false, null)
        ON DUPLICATE KEY UPDATE club=club
    """).setParameter(1, name).executeUpdate();

    return ResponseEntity.ok(ok());
}
    @DeleteMapping("/clubs/{club}")
    @Transactional
    public ResponseEntity<?> deleteClub(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @PathVariable String club) {
        requireAdmin(token);
        em.createNativeQuery("DELETE FROM clubs WHERE club_name=?")
                .setParameter(1, club)
                .executeUpdate();
        return ResponseEntity.ok(ok());
    }

    // ===================== EVENTS =====================
    @GetMapping("/events")
    public ResponseEntity<?> listEvents(@RequestParam(value = "club", required = false) String club) {
        String sql = "SELECT id, club, title, date, reg_link, photo_url FROM events";
        if (notBlank(club)) sql += " WHERE club=?";
        sql += " ORDER BY date DESC, id DESC";

        Query q = em.createNativeQuery(sql);
        if (notBlank(club)) q.setParameter(1, club);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", ((Number) r[0]).longValue());
            m.put("club", String.valueOf(r[1]));
            m.put("title", String.valueOf(r[2]));
            m.put("date", String.valueOf(r[3]));
            m.put("regLink", r[4] == null ? "" : String.valueOf(r[4]));
            m.put("photoUrl", r[5] == null ? "" : String.valueOf(r[5]));
            items.add(m);
        }
        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping(value = "/admin/event", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Transactional
    public ResponseEntity<?> addEvent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                      @RequestParam String club,
                                      @RequestParam String title,
                                      @RequestParam String date,
                                      @RequestParam(required = false) String regLink,
                                      @RequestPart(required = false) MultipartFile photo) throws IOException {
        requireAdmin(token);
        if (!notBlank(club) || !notBlank(title) || !notBlank(date)) throw new RuntimeException("club/title/date required");

        String photoUrl = saveUpload(photo);

        em.createNativeQuery("""
            INSERT INTO events(club,title,date,reg_link,photo_url)
            VALUES (?,?,?,?,?)
        """)
                .setParameter(1, club)
                .setParameter(2, title)
                .setParameter(3, LocalDate.parse(date))
                .setParameter(4, notBlank(regLink) ? regLink.trim() : null)
                .setParameter(5, photoUrl)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    @DeleteMapping("/events/{id}")
    @Transactional
    public ResponseEntity<?> deleteEvent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                         @PathVariable long id) {
        requireAdmin(token);

        em.createNativeQuery("DELETE FROM events WHERE id=?")
                .setParameter(1, id)
                .executeUpdate();

        em.createNativeQuery("DELETE FROM livescores WHERE event_id=?").setParameter(1, id).executeUpdate();
        em.createNativeQuery("DELETE FROM certificates WHERE event_id=?").setParameter(1, id).executeUpdate();

        return ResponseEntity.ok(ok());
    }

    // ===================== CONTENTS =====================
    @GetMapping("/contents")
    public ResponseEntity<?> listContents(@RequestParam(value = "club", required = false) String club) {
        String sql = "SELECT id, club, title, date FROM contents";
        if (notBlank(club)) sql += " WHERE club=?";
        sql += " ORDER BY date DESC, id DESC";

        Query q = em.createNativeQuery(sql);
        if (notBlank(club)) q.setParameter(1, club);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", ((Number) r[0]).longValue());
            m.put("club", String.valueOf(r[1]));
            m.put("title", String.valueOf(r[2]));
            m.put("date", String.valueOf(r[3]));
            items.add(m);
        }
        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping(value = "/admin/content", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Transactional
    public ResponseEntity<?> addContent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @RequestParam String club,
                                        @RequestParam String title,
                                        @RequestParam String date,
                                        @RequestParam(required = false) String desc,
                                        @RequestParam(required = false) String youtubeLinks,
                                        @RequestPart(required = false) List<MultipartFile> photos,
                                        @RequestPart(required = false) MultipartFile report) throws IOException {
        requireAdmin(token);
        if (!notBlank(club) || !notBlank(title) || !notBlank(date)) throw new RuntimeException("club/title/date required");

        List<String> photoUrls = new ArrayList<>();
        if (photos != null) {
            for (MultipartFile p : photos) {
                if (p != null && !p.isEmpty()) photoUrls.add(saveUpload(p));
            }
        }
        String reportUrl = saveUpload(report);
        String photosStr = String.join("\n", photoUrls);

        em.createNativeQuery("""
            INSERT INTO contents(club,title,date,descr,youtube_links,photo_urls,report_url)
            VALUES (?,?,?,?,?,?,?)
        """)
                .setParameter(1, club)
                .setParameter(2, title)
                .setParameter(3, LocalDate.parse(date))
                .setParameter(4, notBlank(desc) ? desc : null)
                .setParameter(5, notBlank(youtubeLinks) ? youtubeLinks : null)
                .setParameter(6, notBlank(photosStr) ? photosStr : null)
                .setParameter(7, reportUrl)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    @GetMapping("/content/details")
    public ResponseEntity<?> contentDetails(@RequestParam String club,
                                           @RequestParam String title,
                                           @RequestParam String date) {
        Query q = em.createNativeQuery("""
            SELECT descr, youtube_links, photo_urls, report_url
            FROM contents
            WHERE club=? AND title=? AND date=?
            ORDER BY id DESC
            LIMIT 1
        """);
        q.setParameter(1, club);
        q.setParameter(2, title);
        q.setParameter(3, LocalDate.parse(date));

        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) throw new RuntimeException("No content found");

        Object[] r = rows.get(0);
        String desc = r[0] == null ? "" : String.valueOf(r[0]);
        String yt = r[1] == null ? "" : String.valueOf(r[1]);
        String photosStr = r[2] == null ? "" : String.valueOf(r[2]);
        String reportUrl = r[3] == null ? "" : String.valueOf(r[3]);

        List<String> photoUrls = new ArrayList<>();
        if (notBlank(photosStr)) {
            for (String line : photosStr.split("\\R")) {
                if (notBlank(line)) photoUrls.add(line.trim());
            }
        }

        List<String> ytLinks = new ArrayList<>();
        if (notBlank(yt)) {
            for (String line : yt.split("\\R")) {
                if (notBlank(line)) ytLinks.add(line.trim());
            }
        }

        Map<String, Object> item = new LinkedHashMap<>();
        item.put("desc", desc);
        item.put("youtubeLinks", ytLinks);
        item.put("photoUrls", photoUrls);
        item.put("reportUrl", reportUrl);

        return ResponseEntity.ok(ok("item", item));
    }

    @DeleteMapping("/contents/{id}")
    @Transactional
    public ResponseEntity<?> deleteContent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                          @PathVariable long id) {
        requireAdmin(token);
        em.createNativeQuery("DELETE FROM contents WHERE id=?")
                .setParameter(1, id)
                .executeUpdate();
        return ResponseEntity.ok(ok());
    }

    // ===================== ADMIN USERS =====================
    @PostMapping("/admin/users")
    @Transactional
    public ResponseEntity<?> createUser(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @RequestBody Map<String, Object> body) {
        requireAdmin(token);

        String username = String.valueOf(body.getOrDefault("username", "")).trim();
        String password = String.valueOf(body.getOrDefault("password", ""));
        String role = String.valueOf(body.getOrDefault("role", "user")).trim();

        if (!notBlank(username) || !notBlank(password)) throw new RuntimeException("username/password required");
        if (!("admin".equalsIgnoreCase(role) || "user".equalsIgnoreCase(role))) role = "user";
        if (userExists(username)) throw new RuntimeException("User already exists");

        createUserInternal(username, password, role.toLowerCase());
        return ResponseEntity.ok(ok());
    }

    @GetMapping("/admin/users/{username}")
    public ResponseEntity<?> getUser(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                     @PathVariable String username) {
        requireAdmin(token);

        Map<String, Object> u = getUserRow(username);
        if (u == null) throw new RuntimeException("User not found");

        Long uid = ((Number) u.get("id")).longValue();
        Map<String, Object> p = getProfileRowByUserId(uid);

        return ResponseEntity.ok(ok("user", u, "profile", p == null ? new LinkedHashMap<>() : p));
    }

    @PutMapping("/admin/users/{username}")
    @Transactional
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> updateUser(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @PathVariable String username,
                                        @RequestBody Map<String, Object> payload) {
        requireAdmin(token);

        Object uObj = payload.get("user");
        Object pObj = payload.get("profile");

        Map<String, Object> u = (uObj instanceof Map) ? (Map<String, Object>) uObj : new LinkedHashMap<>();
        Map<String, Object> p = (pObj instanceof Map) ? (Map<String, Object>) pObj : new LinkedHashMap<>();

        String newPass = String.valueOf(u.getOrDefault("password", ""));
        String newRole = String.valueOf(u.getOrDefault("role", "user")).trim();

        if (!notBlank(newPass)) throw new RuntimeException("Password cannot be empty");
        if (!("admin".equalsIgnoreCase(newRole) || "user".equalsIgnoreCase(newRole))) newRole = "user";

        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");

        em.createNativeQuery("UPDATE users SET password=?, role=? WHERE username=?")
                .setParameter(1, newPass)
                .setParameter(2, newRole.toLowerCase())
                .setParameter(3, username)
                .executeUpdate();

        String dobStr = String.valueOf(p.getOrDefault("dob", "")).trim();

        em.createNativeQuery("""
            INSERT INTO user_profiles(user_id,name,phone,email,branch,gender,dob,address)
            VALUES (?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE
              name=VALUES(name),
              phone=VALUES(phone),
              email=VALUES(email),
              branch=VALUES(branch),
              gender=VALUES(gender),
              dob=VALUES(dob),
              address=VALUES(address)
        """)
                .setParameter(1, uid)
                .setParameter(2, String.valueOf(p.getOrDefault("name", "")).trim())
                .setParameter(3, String.valueOf(p.getOrDefault("phone", "")).trim())
                .setParameter(4, String.valueOf(p.getOrDefault("email", "")).trim())
                .setParameter(5, String.valueOf(p.getOrDefault("branch", "")).trim())
                .setParameter(6, String.valueOf(p.getOrDefault("gender", "")).trim())
                .setParameter(7, notBlank(dobStr) ? LocalDate.parse(dobStr) : null)
                .setParameter(8, String.valueOf(p.getOrDefault("address", "")).trim())
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    // ===================== ME: PROFILE =====================
    @GetMapping("/me/profile")
    public ResponseEntity<?> myProfile(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        String username = requireTokenUser(token);
        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");
        Map<String, Object> p = getProfileRowByUserId(uid);
        return ResponseEntity.ok(ok("profile", p));
    }

    @PostMapping("/me/profile")
    @Transactional
    public ResponseEntity<?> saveMyProfile(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                          @RequestBody Map<String, Object> profile) {
        String username = requireTokenUser(token);
        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");

        String name = String.valueOf(profile.getOrDefault("name", "")).trim();
        String phone = String.valueOf(profile.getOrDefault("phone", "")).trim();
        String email = String.valueOf(profile.getOrDefault("email", "")).trim();
        String branch = String.valueOf(profile.getOrDefault("branch", "")).trim();
        String gender = String.valueOf(profile.getOrDefault("gender", "")).trim();
        String dobStr = String.valueOf(profile.getOrDefault("dob", "")).trim();
        String address = String.valueOf(profile.getOrDefault("address", "")).trim();

        em.createNativeQuery("""
            INSERT INTO user_profiles(user_id,name,phone,email,branch,gender,dob,address)
            VALUES (?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE
              name=VALUES(name),
              phone=VALUES(phone),
              email=VALUES(email),
              branch=VALUES(branch),
              gender=VALUES(gender),
              dob=VALUES(dob),
              address=VALUES(address)
        """)
                .setParameter(1, uid)
                .setParameter(2, name)
                .setParameter(3, phone)
                .setParameter(4, email)
                .setParameter(5, branch)
                .setParameter(6, gender)
                .setParameter(7, notBlank(dobStr) ? LocalDate.parse(dobStr) : null)
                .setParameter(8, address)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    // ===================== ME: CHANGE PASSWORD =====================
    @PostMapping("/me/change-password")
    @Transactional
    public ResponseEntity<?> changePassword(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                           @RequestBody Map<String, Object> body) {
        String username = requireTokenUser(token);

        String oldPassword = String.valueOf(body.getOrDefault("oldPassword", ""));
        String newPassword = String.valueOf(body.getOrDefault("newPassword", ""));
        if (!notBlank(oldPassword) || !notBlank(newPassword)) throw new RuntimeException("oldPassword/newPassword required");

        Map<String, Object> u = getUserRow(username);
        if (u == null) throw new RuntimeException("User not found");
        if (!Objects.equals(String.valueOf(u.get("password")), oldPassword)) throw new RuntimeException("Old password is wrong");

        em.createNativeQuery("UPDATE users SET password=? WHERE username=?")
                .setParameter(1, newPassword)
                .setParameter(2, username)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    // ===================== RECRUITMENT =====================
    @GetMapping("/recruitments")
    public ResponseEntity<?> adminRecruitments(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        requireAdmin(token);

        Query q = em.createNativeQuery("SELECT club, is_open, link FROM recruitments ORDER BY club ASC");
        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("club", String.valueOf(r[0]));
            m.put("open", (Boolean) r[1]);
            m.put("link", r[2] == null ? "" : String.valueOf(r[2]));
            items.add(m);
        }
        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping("/recruitments/open")
    @Transactional
    public ResponseEntity<?> openRecruit(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                         @RequestBody Map<String, Object> body) {
        requireAdmin(token);

        String club = String.valueOf(body.getOrDefault("club", "")).trim();
        String link = String.valueOf(body.getOrDefault("link", "")).trim();
        if (!notBlank(club) || !notBlank(link)) throw new RuntimeException("club/link required");

        em.createNativeQuery("""
            INSERT INTO recruitments(club,is_open,link)
            VALUES (?,true,?)
            ON DUPLICATE KEY UPDATE is_open=true, link=VALUES(link), updated_at=CURRENT_TIMESTAMP
        """)
                .setParameter(1, club)
                .setParameter(2, link)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    @PostMapping("/recruitments/close")
    @Transactional
    public ResponseEntity<?> closeRecruit(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                          @RequestBody Map<String, Object> body) {
        requireAdmin(token);

        String club = String.valueOf(body.getOrDefault("club", "")).trim();
        if (!notBlank(club)) throw new RuntimeException("club required");

        em.createNativeQuery("""
            INSERT INTO recruitments(club,is_open,link)
            VALUES (?,false,null)
            ON DUPLICATE KEY UPDATE is_open=false, updated_at=CURRENT_TIMESTAMP
        """)
                .setParameter(1, club)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    @GetMapping("/recruitments/open")
    public ResponseEntity<?> openRecruitmentsPublic() {
        Query q = em.createNativeQuery("SELECT club, link FROM recruitments WHERE is_open=true ORDER BY club ASC");
        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("club", String.valueOf(r[0]));
            m.put("link", r[1] == null ? "" : String.valueOf(r[1]));
            items.add(m);
        }
        return ResponseEntity.ok(ok("items", items));
    }

    // ===================== CERTIFICATE =====================
    @PostMapping(value = "/admin/certificates/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Transactional
    public ResponseEntity<?> uploadCertificate(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                               @RequestParam String club,
                                               @RequestParam long eventId,
                                               @RequestParam String regNo,
                                               @RequestPart MultipartFile file) throws IOException {
        requireAdmin(token);

        if (!notBlank(club) || !notBlank(regNo) || file == null || file.isEmpty()) {
            throw new RuntimeException("club/eventId/regNo/file required");
        }

        String url = saveUpload(file);

        em.createNativeQuery("""
            INSERT INTO certificates(club,event_id,reg_no,file_url)
            VALUES (?,?,?,?)
            ON DUPLICATE KEY UPDATE file_url=VALUES(file_url), created_at=CURRENT_TIMESTAMP
        """)
                .setParameter(1, club)
                .setParameter(2, eventId)
                .setParameter(3, regNo.trim())
                .setParameter(4, url)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    @GetMapping("/certificates/get")
    public ResponseEntity<?> getCertificate(@RequestParam String club,
                                           @RequestParam long eventId,
                                           @RequestParam String regNo) {
        Query q = em.createNativeQuery("""
            SELECT file_url FROM certificates
            WHERE club=? AND event_id=? AND reg_no=?
            LIMIT 1
        """);
        q.setParameter(1, club);
        q.setParameter(2, eventId);
        q.setParameter(3, regNo.trim());

        List<?> rows = q.getResultList();
        if (rows.isEmpty()) throw new RuntimeException("Not found");
        String url = rows.get(0) == null ? "" : String.valueOf(rows.get(0));
        return ResponseEntity.ok(ok("fileUrl", url));
    }

    // ===================== LIVESCORE =====================
    @PostMapping("/admin/livescore/save")
    @Transactional
    public ResponseEntity<?> saveLiveScore(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                          @RequestBody Map<String, Object> body) {
        requireAdmin(token);

        String club = String.valueOf(body.getOrDefault("club", "")).trim();
        long eventId = Long.parseLong(String.valueOf(body.getOrDefault("eventId", "0")));
        Object ts = body.get("teamScores");

        if (!notBlank(club) || eventId <= 0 || !(ts instanceof List)) {
            throw new RuntimeException("club/eventId/teamScores required");
        }

        List<?> list = (List<?>) ts;
        for (Object o : list) {
            if (!(o instanceof Map)) continue;

            Map<?, ?> raw = (Map<?, ?>) o;

            Object tnoObj = raw.get("teamNo");
            Object scoreObj = raw.get("score");

            int teamNo = 0;
            int score = 0;

            if (tnoObj != null) teamNo = Integer.parseInt(String.valueOf(tnoObj));
            if (scoreObj != null) score = Integer.parseInt(String.valueOf(scoreObj));

            if (teamNo <= 0) continue;
            if (score < 0) score = 0;
            if (score > 100) score = 100;

            em.createNativeQuery("""
                INSERT INTO livescores(club,event_id,team_no,score)
                VALUES (?,?,?,?)
                ON DUPLICATE KEY UPDATE score=VALUES(score), updated_at=CURRENT_TIMESTAMP
            """)
                    .setParameter(1, club)
                    .setParameter(2, eventId)
                    .setParameter(3, teamNo)
                    .setParameter(4, score)
                    .executeUpdate();
        }

        return ResponseEntity.ok(ok());
    }

    @GetMapping("/livescore/get")
    public ResponseEntity<?> getLiveScore(@RequestParam String club,
                                         @RequestParam long eventId) {
        Query q = em.createNativeQuery("""
            SELECT team_no, score
            FROM livescores
            WHERE club=? AND event_id=?
            ORDER BY team_no ASC
        """);
        q.setParameter(1, club);
        q.setParameter(2, eventId);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("teamNo", ((Number) r[0]).intValue());
            m.put("score", ((Number) r[1]).intValue());
            items.add(m);
        }
        return ResponseEntity.ok(ok("items", items));
    }

    // ===================== OTP: FORGOT PASSWORD =====================
    @PostMapping("/auth/forgot/send-otp")
    public ResponseEntity<?> forgotSendOtp(@RequestBody Map<String, Object> body) {
        String username = String.valueOf(body.getOrDefault("username", "")).trim();
        if (!notBlank(username)) throw new RuntimeException("username required");
        if (!userExists(username)) throw new RuntimeException("User not found");

        String email = getEmailForUser(username);
        if (!notBlank(email)) throw new RuntimeException("No email found in profile. Complete profile first.");

        String otp = genOtp6();
        Instant exp = Instant.now().plusSeconds(5 * 60);

        // ✅ DB insert in its own safe transaction
        otpService.createOtp(username, "FORGOT", otp, exp);

        // ✅ mail send outside transaction (no rollback-only issue)
        sendOtpMail(email, "CMS OTP (Forgot Password)", "Your OTP is: " + otp + "\nValid for 5 minutes.");

        return ResponseEntity.ok(ok());
    }

    @PostMapping("/auth/forgot/verify-otp")
    public ResponseEntity<?> forgotVerifyOtp(@RequestBody Map<String, Object> body) {
        String username = String.valueOf(body.getOrDefault("username", "")).trim();
        String otp = String.valueOf(body.getOrDefault("otp", "")).trim();
        if (!notBlank(username) || !notBlank(otp)) throw new RuntimeException("username/otp required");

        Map<String, Object> row = otpService.getLatestOtp(username, "FORGOT");
        if (row == null) throw new RuntimeException("OTP not found");

        Instant exp = (Instant) row.get("expiresAt");
        if (Instant.now().isAfter(exp)) throw new RuntimeException("OTP expired");
        if (!Objects.equals(String.valueOf(row.get("otp")), otp)) throw new RuntimeException("Invalid OTP");

        otpService.markOtpVerified(((Number) row.get("id")).longValue());
        return ResponseEntity.ok(ok());
    }

    @PostMapping("/auth/forgot/reset")
    @Transactional
    public ResponseEntity<?> forgotReset(@RequestBody Map<String, Object> body) {
        String username = String.valueOf(body.getOrDefault("username", "")).trim();
        String otp = String.valueOf(body.getOrDefault("otp", "")).trim();
        String newPassword = String.valueOf(body.getOrDefault("newPassword", ""));
        if (!notBlank(username) || !notBlank(otp) || !notBlank(newPassword)) {
            throw new RuntimeException("username/otp/newPassword required");
        }

        Map<String, Object> row = otpService.getLatestOtp(username, "FORGOT");
        if (row == null) throw new RuntimeException("OTP not found");

        Instant exp = (Instant) row.get("expiresAt");
        if (Instant.now().isAfter(exp)) throw new RuntimeException("OTP expired");
        if (!Objects.equals(String.valueOf(row.get("otp")), otp)) throw new RuntimeException("Invalid OTP");
        if (!Boolean.TRUE.equals(row.get("verified"))) throw new RuntimeException("OTP not verified");

        em.createNativeQuery("UPDATE users SET password=? WHERE username=?")
                .setParameter(1, newPassword)
                .setParameter(2, username)
                .executeUpdate();

        return ResponseEntity.ok(ok());
    }

    // ===================== OTP: PROFILE EDIT =====================
    @PostMapping("/me/profile/send-otp")
    public ResponseEntity<?> profileSendOtp(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        String username = requireTokenUser(token);

        String email = getEmailForUser(username);
        if (!notBlank(email)) throw new RuntimeException("No email in profile. Complete profile first.");

        String otp = genOtp6();
        Instant exp = Instant.now().plusSeconds(5 * 60);

        otpService.createOtp(username, "PROFILE_EDIT", otp, exp);

        sendOtpMail(email, "CMS OTP (Edit Profile)", "Your OTP is: " + otp + "\nValid for 5 minutes.");

        return ResponseEntity.ok(ok());
    }

    @PostMapping("/me/profile/verify-otp")
    public ResponseEntity<?> profileVerifyOtp(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                              @RequestBody Map<String, Object> body) {
        String username = requireTokenUser(token);
        String otp = String.valueOf(body.getOrDefault("otp", "")).trim();
        if (!notBlank(otp)) throw new RuntimeException("otp required");

        Map<String, Object> row = otpService.getLatestOtp(username, "PROFILE_EDIT");
        if (row == null) throw new RuntimeException("OTP not found");

        Instant exp = (Instant) row.get("expiresAt");
        if (Instant.now().isAfter(exp)) throw new RuntimeException("OTP expired");
        if (!Objects.equals(String.valueOf(row.get("otp")), otp)) throw new RuntimeException("Invalid OTP");

        otpService.markOtpVerified(((Number) row.get("id")).longValue());
        return ResponseEntity.ok(ok());
    }
}

/**
 * ✅ OTP Service (separate bean) so @Transactional works properly.
 */
@Service
class OtpService {

    @PersistenceContext
    private EntityManager em;

    @org.springframework.transaction.annotation.Transactional(propagation = Propagation.REQUIRES_NEW)
    public void createOtp(String username, String purpose, String otp, Instant expiresAt) {
        em.createNativeQuery("""
            INSERT INTO otps(username, purpose, otp, expires_at, verified)
            VALUES (?,?,?,?,false)
        """)
                .setParameter(1, username)
                .setParameter(2, purpose)
                .setParameter(3, otp)
                .setParameter(4, Timestamp.from(expiresAt))
                .executeUpdate();
    }

    public Map<String, Object> getLatestOtp(String username, String purpose) {
        Query q = em.createNativeQuery("""
            SELECT id, otp, expires_at, verified
            FROM otps
            WHERE username=? AND purpose=?
            ORDER BY id DESC
            LIMIT 1
        """);
        q.setParameter(1, username);
        q.setParameter(2, purpose);

        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) return null;

        Object[] r = rows.get(0);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", ((Number) r[0]).longValue());
        m.put("otp", String.valueOf(r[1]));
        m.put("expiresAt", ((Timestamp) r[2]).toInstant());
        m.put("verified", (Boolean) r[3]);
        return m;
    }

    @org.springframework.transaction.annotation.Transactional
    public void markOtpVerified(long otpId) {
        em.createNativeQuery("UPDATE otps SET verified=true WHERE id=?")
                .setParameter(1, otpId)
                .executeUpdate();
    }
}

/**
 * ✅ Global error handler (prevents rollback-only error from try/catch patterns)
 */
@RestControllerAdvice
class ApiExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntime(RuntimeException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", false);
        body.put("message", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAny(Exception e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", false);
        body.put("message", "Server error: " + e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}

/**
 * ✅ Upload controller at ROOT:
 *     http://localhost:8080/uploads/<filename>
 */
@RestController
@CrossOrigin(origins = "*")
class UploadController {

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    @GetMapping("/uploads/{filename:.+}")
    public ResponseEntity<Resource> getUpload(@PathVariable String filename) {
        try {
            Path file = Paths.get(uploadDir).resolve(filename).normalize();
            Resource resource = new UrlResource(file.toUri());
            if (!resource.exists()) return ResponseEntity.notFound().build();

            String ct = "application/octet-stream";
            String f = filename.toLowerCase();
            if (f.endsWith(".png")) ct = "image/png";
            else if (f.endsWith(".jpg") || f.endsWith(".jpeg")) ct = "image/jpeg";
            else if (f.endsWith(".gif")) ct = "image/gif";
            else if (f.endsWith(".pdf")) ct = "application/pdf";

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(ct))
                    .header(HttpHeaders.CACHE_CONTROL, "no-cache")
                    .body(resource);

        } catch (MalformedURLException e) {
            return ResponseEntity.badRequest().build();
        }
    }
}