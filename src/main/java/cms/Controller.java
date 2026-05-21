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
import org.springframework.http.ContentDisposition;
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

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class Controller {

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    @PersistenceContext
    private EntityManager em;

    private final JavaMailSender mailSender;
    private final OtpService otpService;

    public Controller(JavaMailSender mailSender, OtpService otpService) {
        this.mailSender = mailSender;
        this.otpService = otpService;
    }

    private final Map<String, String> tokenToUser = new ConcurrentHashMap<>();
    private final Map<String, String> tokenToRole = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    // =========================================================
    // RESPONSE HELPERS
    // =========================================================
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

    private boolean toBool(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean b) return b;
        if (v instanceof Number n) return n.intValue() != 0;
        String s = String.valueOf(v).trim();
        return "true".equalsIgnoreCase(s) || "1".equals(s);
    }

    private String nz(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    private int toInt(Object v, int defaultValue) {
        if (v == null) return defaultValue;
        if (v instanceof Number n) return n.intValue();
        String s = String.valueOf(v).trim();
        if (s.isEmpty()) return defaultValue;
        return Integer.parseInt(s);
    }

    private String normalizeRole(String role) {
        String r = nz(role).trim().toLowerCase();
        if ("admin".equals(r)) return "admin";
        if ("club_coordinator".equals(r) || "coordinator".equals(r)) return "club_coordinator";
        return "user";
    }

    // =========================================================
    // AUTH HELPERS
    // =========================================================
    private String requireTokenUser(String token) {
        if (!notBlank(token)) throw new RuntimeException("Missing token");
        String user = tokenToUser.get(token);
        if (!notBlank(user)) throw new RuntimeException("Invalid session. Login again.");
        return user;
    }

    private String requireTokenRole(String token) {
        if (!notBlank(token)) throw new RuntimeException("Missing token");
        String role = tokenToRole.get(token);
        if (!notBlank(role)) throw new RuntimeException("Invalid session. Login again.");
        return role;
    }

    private void requireAdmin(String token) {
        String role = requireTokenRole(token);
        if (!"admin".equalsIgnoreCase(role)) throw new RuntimeException("Admin only");
    }

    private String requireAdminOrCoordinator(String token) {
        String role = requireTokenRole(token);
        if (!"admin".equalsIgnoreCase(role) && !"club_coordinator".equalsIgnoreCase(role)) {
            throw new RuntimeException("Admin/Coordinator only");
        }
        return role;
    }

    private void requireClubAccess(String token, String club) {
        String username = requireTokenUser(token);
        String role = requireTokenRole(token);

        if ("admin".equalsIgnoreCase(role)) return;

        if ("club_coordinator".equalsIgnoreCase(role)) {
            String myClub = coordinatorClubOf(username);
            if (!Objects.equals(myClub, club)) {
                throw new RuntimeException("You can access only your own club");
            }
            return;
        }

        throw new RuntimeException("Access denied");
    }

    private String newToken() {
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
    }

    // =========================================================
    // FILE HELPERS
    // =========================================================
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

    // =========================================================
    // DB HELPERS
    // =========================================================
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

    private Map<String, Object> getUserRow(String username) {
        Query q = em.createNativeQuery("SELECT id, username, password, role FROM users WHERE username=?");
        q.setParameter(1, username);
        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) return null;

        Object[] r = rows.get(0);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", ((Number) r[0]).longValue());
        m.put("username", nz(r[1]));
        m.put("password", nz(r[2]));
        m.put("role", nz(r[3]));
        return m;
    }

    private String coordinatorClubOf(String username) {
        Query q = em.createNativeQuery("SELECT club_name FROM club_coordinators WHERE username=? LIMIT 1");
        q.setParameter(1, username);
        List<?> rows = q.getResultList();
        if (rows.isEmpty()) return null;
        return nz(rows.get(0));
    }

    private Long eventIdExists(long id) {
        Query q = em.createNativeQuery("SELECT id FROM events WHERE id=?");
        q.setParameter(1, id);
        List<?> rows = q.getResultList();
        if (rows.isEmpty()) return null;
        return ((Number) rows.get(0)).longValue();
    }

    private String eventClubOf(long eventId) {
        Query q = em.createNativeQuery("SELECT club FROM events WHERE id=?");
        q.setParameter(1, eventId);
        List<?> rows = q.getResultList();
        if (rows.isEmpty()) return null;
        return nz(rows.get(0));
    }

    private String contentClubOf(long contentId) {
        Query q = em.createNativeQuery("SELECT club FROM contents WHERE id=?");
        q.setParameter(1, contentId);
        List<?> rows = q.getResultList();
        if (rows.isEmpty()) return null;
        return nz(rows.get(0));
    }

    private Map<String, Object> getProfileRowByUserId(Long userId) {
        Query q = em.createNativeQuery("""
            SELECT name, phone, email, branch, gender, dob, address,
                   club_name, club_role, club_joined_at
            FROM user_profiles
            WHERE user_id=?
        """);
        q.setParameter(1, userId);

        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) return null;

        Object[] r = rows.get(0);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", nz(r[0]));
        m.put("phone", nz(r[1]));
        m.put("email", nz(r[2]));
        m.put("branch", nz(r[3]));
        m.put("gender", nz(r[4]));
        m.put("dob", nz(r[5]));
        m.put("address", nz(r[6]));
        m.put("club_name", nz(r[7]));
        m.put("club_role", nz(r[8]));
        m.put("club_joined_at", nz(r[9]));
        return m;
    }

    private boolean isProfileComplete(Map<String, Object> p) {
        if (p == null) return false;
        return notBlank(nz(p.get("name")))
                && notBlank(nz(p.get("address")))
                && notBlank(nz(p.get("phone")))
                && notBlank(nz(p.get("email")))
                && notBlank(nz(p.get("branch")))
                && notBlank(nz(p.get("gender")))
                && notBlank(nz(p.get("dob")));
    }

    @Transactional
    private void createUserInternal(String username, String password, String role) {
        em.createNativeQuery("INSERT INTO users(username,password,role) VALUES (?,?,?)")
                .setParameter(1, username)
                .setParameter(2, password)
                .setParameter(3, role)
                .executeUpdate();
    }

    @Transactional
    private void upsertCoordinatorMapping(String username, String clubName) {
        em.createNativeQuery("DELETE FROM club_coordinators WHERE username=?")
                .setParameter(1, username)
                .executeUpdate();

        if (notBlank(clubName)) {
            em.createNativeQuery("INSERT INTO club_coordinators(username,club_name) VALUES (?,?)")
                    .setParameter(1, username)
                    .setParameter(2, clubName)
                    .executeUpdate();
        }
    }

    @Transactional
    private void upsertProfile(Long userId,
                               String name,
                               String phone,
                               String email,
                               String branch,
                               String gender,
                               String dobStr,
                               String address,
                               String clubName,
                               String clubRole) {
        em.createNativeQuery("""
            INSERT INTO user_profiles(
                user_id,name,phone,email,branch,gender,dob,address,
                club_name,club_role,club_joined_at
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE
                name=VALUES(name),
                phone=VALUES(phone),
                email=VALUES(email),
                branch=VALUES(branch),
                gender=VALUES(gender),
                dob=VALUES(dob),
                address=VALUES(address),
                club_name=VALUES(club_name),
                club_role=VALUES(club_role),
                club_joined_at=VALUES(club_joined_at)
        """)
                .setParameter(1, userId)
                .setParameter(2, name)
                .setParameter(3, phone)
                .setParameter(4, email)
                .setParameter(5, branch)
                .setParameter(6, gender)
                .setParameter(7, notBlank(dobStr) ? LocalDate.parse(dobStr) : null)
                .setParameter(8, address)
                .setParameter(9, notBlank(clubName) ? clubName : null)
                .setParameter(10, notBlank(clubRole) ? clubRole : null)
                .setParameter(11, notBlank(clubName) ? Timestamp.from(Instant.now()) : null)
                .executeUpdate();
    }

    private String getEmailForUser(String username) {
        Long uid = userIdOf(username);
        if (uid == null) return null;
        Map<String, Object> p = getProfileRowByUserId(uid);
        if (p == null) return null;
        String email = nz(p.get("email")).trim();
        return notBlank(email) ? email : null;
    }

    private void sendCongratsMail(String toEmail, String username, String club, String roleName) {
        if (!notBlank(toEmail)) return;
        if (mailSender == null) throw new RuntimeException("MailSender not configured");

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(toEmail);
        msg.setSubject("Congratulations - Club Recruitment Selected");
        msg.setText(
                "Dear " + username + ",\n\n" +
                "Congratulations! You have been selected for " + club + ".\n" +
                "Role: " + (notBlank(roleName) ? roleName : "Club Member") + "\n\n" +
                "Welcome to the team.\n\n" +
                "Regards,\n" +
                "CMS Admin"
        );
        mailSender.send(msg);
    }

    // =========================================================
    // LOGIN / LOGOUT
    // =========================================================
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, Object> body) {
        String username = nz(body.get("username")).trim();
        String password = nz(body.get("password"));

        if (!notBlank(username) || !notBlank(password)) {
            throw new RuntimeException("username/password required");
        }

        Map<String, Object> u = getUserRow(username);
        if (u == null) throw new RuntimeException("Invalid username/password");
        if (!Objects.equals(nz(u.get("password")), password)) {
            throw new RuntimeException("Invalid username/password");
        }

        Long uid = ((Number) u.get("id")).longValue();
        Map<String, Object> p = getProfileRowByUserId(uid);
        boolean complete = isProfileComplete(p);

        String role = normalizeRole(nz(u.get("role")));
        String token = newToken();

        tokenToUser.put(token, username);
        tokenToRole.put(token, role);

        String club = null;
        if ("club_coordinator".equals(role)) {
            club = coordinatorClubOf(username);
        } else if (p != null && notBlank(nz(p.get("club_name")))) {
            club = nz(p.get("club_name"));
        }

        return ResponseEntity.ok(ok(
                "token", token,
                "username", username,
                "role", role,
                "profileComplete", complete,
                "club", club
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        if (notBlank(token)) {
            tokenToUser.remove(token);
            tokenToRole.remove(token);
        }
        return ResponseEntity.ok(ok("message", "Logged out"));
    }

    // =========================================================
    // FILE OPEN
    // =========================================================
    @GetMapping("/files")
    public ResponseEntity<Resource> openUploadedFile(@RequestParam("path") String relativePath) throws MalformedURLException {
        if (!notBlank(relativePath)) throw new RuntimeException("path required");

        String normalized = relativePath.startsWith("/uploads/") ? relativePath.substring("/uploads/".length()) : relativePath;
        Path file = Paths.get(uploadDir).resolve(normalized).normalize();
        Resource resource = new UrlResource(file.toUri());
        if (!resource.exists() || !resource.isReadable()) throw new RuntimeException("File not found");

        String filename = file.getFileName().toString().toLowerCase();
        MediaType mediaType = MediaType.APPLICATION_OCTET_STREAM;
        if (filename.endsWith(".pdf")) mediaType = MediaType.APPLICATION_PDF;
        else if (filename.endsWith(".png")) mediaType = MediaType.IMAGE_PNG;
        else if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) mediaType = MediaType.IMAGE_JPEG;
        else if (filename.endsWith(".gif")) mediaType = MediaType.IMAGE_GIF;

        return ResponseEntity.ok()
                .contentType(mediaType)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.inline().filename(file.getFileName().toString()).build().toString())
                .body(resource);
    }

    // =========================================================
    // CLUBS
    // =========================================================
    @GetMapping("/clubs")
    public ResponseEntity<?> clubs() {
        Query q = em.createNativeQuery("SELECT club_name FROM clubs ORDER BY club_name ASC");
        List<?> rows = q.getResultList();
        List<String> items = new ArrayList<>();
        for (Object r : rows) items.add(nz(r));
        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping("/clubs")
    @Transactional
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> addClub(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                     @RequestBody Map<String, Object> body) {
        requireAdmin(token);

        String name = nz(body.get("name")).trim();
        Object coordsObj = body.get("coordinators");

        if (!notBlank(name)) throw new RuntimeException("Club name required");
        if (!(coordsObj instanceof List<?> coords) || coords.size() != 4) {
            throw new RuntimeException("Exactly 4 coordinators required");
        }

        Number exists = (Number) em.createNativeQuery("SELECT COUNT(*) FROM clubs WHERE club_name=?")
                .setParameter(1, name)
                .getSingleResult();
        if (exists.longValue() > 0) throw new RuntimeException("Club already exists");

        em.createNativeQuery("INSERT INTO clubs(club_name) VALUES (?)")
                .setParameter(1, name)
                .executeUpdate();

        for (Object o : coords) {
            if (!(o instanceof Map<?, ?> raw)) throw new RuntimeException("Invalid coordinator item");
            String username = nz(raw.get("username")).trim();
            String password = nz(raw.get("password")).trim();

            if (!notBlank(username) || !notBlank(password)) {
                throw new RuntimeException("Coordinator username/password required");
            }
            if (userExists(username)) throw new RuntimeException("User already exists: " + username);

            createUserInternal(username, password, "club_coordinator");
            upsertCoordinatorMapping(username, name);

            Long uid = userIdOf(username);
            if (uid != null) upsertProfile(uid, "", "", "", "", "", "", "", name, "Coordinator");
        }

        return ResponseEntity.ok(ok("message", "Club created"));
    }

    // alias required by admin frontend
    @PostMapping("/admin/clubs/full")
    @Transactional
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> addClubFull(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                         @RequestBody Map<String, Object> body) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("name", nz(body.get("clubName")).trim());
        normalized.put("coordinators", body.get("coordinators"));
        return addClub(token, normalized);
    }

    @DeleteMapping("/clubs/{club}")
    @Transactional
    public ResponseEntity<?> deleteClub(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @PathVariable String club) {
        requireAdmin(token);

        em.createNativeQuery("DELETE FROM club_coordinators WHERE club_name=?")
                .setParameter(1, club)
                .executeUpdate();
        em.createNativeQuery("DELETE FROM club_members WHERE club=?")
                .setParameter(1, club)
                .executeUpdate();
        em.createNativeQuery("DELETE FROM recruitment_applications WHERE club=?")
                .setParameter(1, club)
                .executeUpdate();
        em.createNativeQuery("DELETE FROM recruitments WHERE club=?")
                .setParameter(1, club)
                .executeUpdate();
        em.createNativeQuery("DELETE FROM clubs WHERE club_name=?")
                .setParameter(1, club)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Club deleted"));
    }

    // =========================================================
    // EVENTS
    // =========================================================
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
            m.put("club", nz(r[1]));
            m.put("title", nz(r[2]));
            m.put("date", nz(r[3]));
            m.put("regLink", nz(r[4]));
            m.put("photoUrl", nz(r[5]));
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
                                      @RequestParam(required = false) String desc,
                                      @RequestParam(required = false) String description,
                                      @RequestPart(required = false) MultipartFile photo) throws IOException {
        requireClubAccess(token, club);
        if (!notBlank(club) || !notBlank(title) || !notBlank(date)) {
            throw new RuntimeException("club/title/date required");
        }

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

        return ResponseEntity.ok(ok("message", "Event saved"));
    }

    @PostMapping(value = "/admin/event/send-mail", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> sendEventMail(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                           @RequestParam String club,
                                           @RequestParam String title,
                                           @RequestParam String description,
                                           @RequestPart(required = false) MultipartFile photo) throws IOException {
        requireClubAccess(token, club);

        if (mailSender == null) throw new RuntimeException("MailSender not configured");

        Query q = em.createNativeQuery("""
            SELECT up.email
            FROM user_profiles up
            WHERE up.email IS NOT NULL AND up.email <> ''
        """);
        List<?> rows = q.getResultList();

        for (Object row : rows) {
            String email = nz(row).trim();
            if (!notBlank(email)) continue;

            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setTo(email);
            msg.setSubject("New Event - " + title + " (" + club + ")");
            msg.setText("Club: " + club + "\nTitle: " + title + "\n\n" + nz(description));
            mailSender.send(msg);
        }

        return ResponseEntity.ok(ok("message", "Mail sent"));
    }

    @DeleteMapping("/events/{id}")
    @Transactional
    public ResponseEntity<?> deleteEvent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                         @PathVariable long id) {
        String club = eventClubOf(id);
        if (!notBlank(club)) throw new RuntimeException("Event not found");

        requireClubAccess(token, club);

        em.createNativeQuery("DELETE FROM events WHERE id=?")
                .setParameter(1, id)
                .executeUpdate();
        em.createNativeQuery("DELETE FROM livescores WHERE event_id=?")
                .setParameter(1, id)
                .executeUpdate();
        em.createNativeQuery("DELETE FROM certificates WHERE event_id=?")
                .setParameter(1, id)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Event deleted"));
    }

    // =========================================================
    // CONTENTS
    // =========================================================
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
            m.put("club", nz(r[1]));
            m.put("title", nz(r[2]));
            m.put("date", nz(r[3]));
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
        requireClubAccess(token, club);

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

        return ResponseEntity.ok(ok("message", "Content saved"));
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
        String photosStr = nz(r[2]);
        String yt = nz(r[1]);

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
        item.put("desc", nz(r[0]));
        item.put("youtubeLinks", ytLinks);
        item.put("photoUrls", photoUrls);
        item.put("reportUrl", nz(r[3]));

        return ResponseEntity.ok(ok("item", item));
    }

    @DeleteMapping("/contents/{id}")
    @Transactional
    public ResponseEntity<?> deleteContent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                           @PathVariable long id) {
        String club = contentClubOf(id);
        if (!notBlank(club)) throw new RuntimeException("Content not found");

        requireClubAccess(token, club);

        em.createNativeQuery("DELETE FROM contents WHERE id=?")
                .setParameter(1, id)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Content deleted"));
    }

    // =========================================================
    // USERS
    // =========================================================
    @GetMapping("/admin/users")
    public ResponseEntity<?> listUsers(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                       @RequestParam(value = "club", required = false) String club) {
        String actor = requireTokenUser(token);
        String role = requireAdminOrCoordinator(token);

        if ("club_coordinator".equalsIgnoreCase(role)) {
            club = coordinatorClubOf(actor);
        }

        String sql = """
            SELECT u.id, u.username, u.password, u.role,
                   p.name, p.phone, p.email, p.branch, p.gender, p.dob, p.address,
                   COALESCE(p.club_name,''), COALESCE(p.club_role,''), COALESCE(p.club_joined_at,'')
            FROM users u
            LEFT JOIN user_profiles p ON p.user_id = u.id
        """;
        if (notBlank(club)) sql += " WHERE COALESCE(p.club_name,'')=? ";
        sql += " ORDER BY u.username ASC";

        Query q = em.createNativeQuery(sql);
        if (notBlank(club)) q.setParameter(1, club);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();

        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", ((Number) r[0]).longValue());
            m.put("username", nz(r[1]));
            m.put("password", nz(r[2]));
            m.put("role", nz(r[3]));
            m.put("name", nz(r[4]));
            m.put("phone", nz(r[5]));
            m.put("email", nz(r[6]));
            m.put("branch", nz(r[7]));
            m.put("gender", nz(r[8]));
            m.put("dob", nz(r[9]));
            m.put("address", nz(r[10]));
            m.put("club", nz(r[11]));
            m.put("clubRole", nz(r[12]));
            m.put("clubJoinedAt", nz(r[13]));

            if ("club_coordinator".equalsIgnoreCase(role)) {
                if (!Objects.equals(nz(m.get("club")), club)) continue;
                if ("admin".equalsIgnoreCase(nz(m.get("role")))) continue;
            }
            items.add(m);
        }

        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping("/admin/users")
    @Transactional
    public ResponseEntity<?> createUser(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @RequestBody Map<String, Object> body) {
        String actor = requireTokenUser(token);
        String actorRole = requireAdminOrCoordinator(token);

        String username = nz(body.get("username")).trim();
        String password = nz(body.get("password"));
        String requestedRole = normalizeRole(nz(body.get("role")));
        String club = nz(body.get("club")).trim();

        if (!notBlank(username) || !notBlank(password)) {
            throw new RuntimeException("username/password required");
        }
        if (userExists(username)) throw new RuntimeException("User already exists");

        String finalRole = requestedRole;
        String finalClub = club;

        if ("club_coordinator".equalsIgnoreCase(actorRole)) {
            finalRole = "user";
            finalClub = coordinatorClubOf(actor);
            if (!notBlank(finalClub)) throw new RuntimeException("Coordinator club not found");
        } else {
            if ("club_coordinator".equals(finalRole) && !notBlank(finalClub)) {
                throw new RuntimeException("Club required for coordinator");
            }
        }

        createUserInternal(username, password, finalRole);

        Long uid = userIdOf(username);
        if (uid != null && notBlank(finalClub)) {
            upsertProfile(uid, "", "", "", "", "", "", "", finalClub,
                    "club_coordinator".equals(finalRole) ? "Coordinator" : "");
        }

        if ("club_coordinator".equals(finalRole)) {
            upsertCoordinatorMapping(username, finalClub);
        }

        return ResponseEntity.ok(ok("message", "User created", "username", username, "role", finalRole, "club", finalClub));
    }

    @GetMapping("/admin/users/{username}")
    public ResponseEntity<?> getUser(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                     @PathVariable String username) {
        String actor = requireTokenUser(token);
        String actorRole = requireAdminOrCoordinator(token);

        Map<String, Object> u = getUserRow(username);
        if (u == null) throw new RuntimeException("User not found");

        Long uid = ((Number) u.get("id")).longValue();
        Map<String, Object> p = getProfileRowByUserId(uid);
        if (p == null) p = new LinkedHashMap<>();

        String role = nz(u.get("role"));
        String club = nz(p.get("club_name"));
        if ("club_coordinator".equalsIgnoreCase(role) && !notBlank(club)) {
            club = nz(coordinatorClubOf(username));
        }

        if ("club_coordinator".equalsIgnoreCase(actorRole)) {
            String myClub = coordinatorClubOf(actor);
            if (!Objects.equals(myClub, club)) {
                throw new RuntimeException("You can access only your own club users");
            }
            if ("admin".equalsIgnoreCase(role)) {
                throw new RuntimeException("Coordinator cannot access admin details");
            }
        }

        Map<String, Object> userBlock = new LinkedHashMap<>();
        userBlock.put("id", u.get("id"));
        userBlock.put("username", nz(u.get("username")));
        userBlock.put("password", nz(u.get("password")));
        userBlock.put("role", role);
        userBlock.put("club", club);

        return ResponseEntity.ok(ok(
                "id", u.get("id"),
                "username", nz(u.get("username")),
                "password", nz(u.get("password")),
                "role", role,
                "club", club,
                "name", nz(p.get("name")),
                "phone", nz(p.get("phone")),
                "email", nz(p.get("email")),
                "branch", nz(p.get("branch")),
                "gender", nz(p.get("gender")),
                "dob", nz(p.get("dob")),
                "address", nz(p.get("address")),
                "user", userBlock,
                "profile", p
        ));
    }

    @PutMapping("/admin/users/{username}")
    @Transactional
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> updateUser(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                        @PathVariable String username,
                                        @RequestBody Map<String, Object> payload) {
        String actor = requireTokenUser(token);
        String actorRole = requireAdminOrCoordinator(token);

        Map<String, Object> u = payload.get("user") instanceof Map<?, ?> userMap
                ? (Map<String, Object>) userMap : new LinkedHashMap<>(payload);
        Map<String, Object> p = payload.get("profile") instanceof Map<?, ?> profileMap
                ? (Map<String, Object>) profileMap : new LinkedHashMap<>(payload);

        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");

        Map<String, Object> existingUser = getUserRow(username);
        Map<String, Object> existingProfile = getProfileRowByUserId(uid);
        if (existingProfile == null) existingProfile = new LinkedHashMap<>();

        String existingRole = nz(existingUser.get("role"));
        String existingClub = nz(existingProfile.get("club_name"));
        if ("club_coordinator".equalsIgnoreCase(existingRole) && !notBlank(existingClub)) {
            existingClub = nz(coordinatorClubOf(username));
        }

        String newPass = nz(u.get("password")).trim();
        if (!notBlank(newPass)) newPass = nz(existingUser.get("password"));

        String newRole = normalizeRole(nz(u.get("role")));
        String newClub = nz(u.get("club")).trim();
        if (!notBlank(newClub)) newClub = nz(p.get("club")).trim();
        if (!notBlank(newClub)) newClub = nz(p.get("club_name")).trim();
        if (!notBlank(newClub)) newClub = existingClub;

        if ("club_coordinator".equalsIgnoreCase(actorRole)) {
            String myClub = coordinatorClubOf(actor);
            if (!Objects.equals(myClub, existingClub)) {
                throw new RuntimeException("You can update only your own club users");
            }
            if ("admin".equalsIgnoreCase(existingRole)) {
                throw new RuntimeException("Coordinator cannot update admin");
            }
            newRole = "user";
            newClub = myClub;
        }

        em.createNativeQuery("UPDATE users SET password=?, role=? WHERE username=?")
                .setParameter(1, newPass)
                .setParameter(2, newRole)
                .setParameter(3, username)
                .executeUpdate();

        if ("club_coordinator".equals(newRole)) {
            if (!notBlank(newClub)) throw new RuntimeException("Club required for coordinator");
            upsertCoordinatorMapping(username, newClub);
        } else {
            em.createNativeQuery("DELETE FROM club_coordinators WHERE username=?")
                    .setParameter(1, username)
                    .executeUpdate();
        }

        upsertProfile(
                uid,
                nz(p.get("name")).trim(),
                nz(p.get("phone")).trim(),
                nz(p.get("email")).trim(),
                nz(p.get("branch")).trim(),
                nz(p.get("gender")).trim(),
                nz(p.get("dob")).trim(),
                nz(p.get("address")).trim(),
                newClub,
                nz(p.get("club_role")).trim()
        );

        return ResponseEntity.ok(ok("message", "User updated", "username", username, "role", newRole, "club", newClub));
    }

    // =========================================================
    // PROFILE / PASSWORD
    // =========================================================
    @GetMapping("/me/profile")
    public ResponseEntity<?> myProfile(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        String username = requireTokenUser(token);
        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");

        Map<String, Object> p = getProfileRowByUserId(uid);
        if (p == null) p = new LinkedHashMap<>();

        if (!notBlank(nz(p.get("club_name")))) {
            p.put("club_name", "");
            p.put("club_role", "");
            p.put("club_joined_at", "");
        }

        return ResponseEntity.ok(ok("profile", p));
    }

    @PostMapping("/me/profile")
    @Transactional
    public ResponseEntity<?> saveMyProfile(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                           @RequestBody Map<String, Object> profile) {
        String username = requireTokenUser(token);
        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");

        Map<String, Object> current = getProfileRowByUserId(uid);
        String clubName = current == null ? "" : nz(current.get("club_name")).trim();
        String clubRole = current == null ? "" : nz(current.get("club_role")).trim();

        upsertProfile(
                uid,
                nz(profile.get("name")).trim(),
                nz(profile.get("phone")).trim(),
                nz(profile.get("email")).trim(),
                nz(profile.get("branch")).trim(),
                nz(profile.get("gender")).trim(),
                nz(profile.get("dob")).trim(),
                nz(profile.get("address")).trim(),
                clubName,
                clubRole
        );

        return ResponseEntity.ok(ok("message", "Profile saved"));
    }

    @PostMapping("/me/change-password")
    @Transactional
    public ResponseEntity<?> changePassword(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                            @RequestBody Map<String, Object> body) {
        String username = requireTokenUser(token);
        String oldPassword = nz(body.get("oldPassword"));
        String newPassword = nz(body.get("newPassword"));

        if (!notBlank(oldPassword) || !notBlank(newPassword)) {
            throw new RuntimeException("oldPassword/newPassword required");
        }

        Map<String, Object> u = getUserRow(username);
        if (u == null) throw new RuntimeException("User not found");
        if (!Objects.equals(nz(u.get("password")), oldPassword)) {
            throw new RuntimeException("Old password is wrong");
        }

        em.createNativeQuery("UPDATE users SET password=? WHERE username=?")
                .setParameter(1, newPassword)
                .setParameter(2, username)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Password changed"));
    }

    // =========================================================
    // CERTIFICATES
    // =========================================================
    @PostMapping(value = "/admin/certificates/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Transactional
    public ResponseEntity<?> uploadCertificate(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                               @RequestParam String club,
                                               @RequestParam long eventId,
                                               @RequestParam String regNo,
                                               @RequestPart MultipartFile file) throws IOException {
        requireClubAccess(token, club);

        if (eventIdExists(eventId) == null) throw new RuntimeException("Event not found");
        String eventClub = eventClubOf(eventId);
        if (!Objects.equals(eventClub, club)) throw new RuntimeException("Event does not belong to selected club");

        String fileUrl = saveUpload(file);

        Number count = (Number) em.createNativeQuery("""
            SELECT COUNT(*)
            FROM certificates
            WHERE club=? AND event_id=? AND reg_no=?
        """)
                .setParameter(1, club)
                .setParameter(2, eventId)
                .setParameter(3, regNo)
                .getSingleResult();

        if (count.longValue() > 0) {
            em.createNativeQuery("""
                UPDATE certificates
                SET file_url=?, updated_at=CURRENT_TIMESTAMP
                WHERE club=? AND event_id=? AND reg_no=?
            """)
                    .setParameter(1, fileUrl)
                    .setParameter(2, club)
                    .setParameter(3, eventId)
                    .setParameter(4, regNo)
                    .executeUpdate();
        } else {
            em.createNativeQuery("""
                INSERT INTO certificates(club,event_id,reg_no,file_url,updated_at)
                VALUES (?,?,?,?,CURRENT_TIMESTAMP)
            """)
                    .setParameter(1, club)
                    .setParameter(2, eventId)
                    .setParameter(3, regNo)
                    .setParameter(4, fileUrl)
                    .executeUpdate();
        }

        return ResponseEntity.ok(ok("message", "Certificate uploaded", "fileUrl", fileUrl));
    }

    @PostMapping(value = "/admin/certificates/upload-by-username", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Transactional
    public ResponseEntity<?> uploadCertificateByUsername(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                                         @RequestParam String club,
                                                         @RequestParam long eventId,
                                                         @RequestParam String username,
                                                         @RequestPart MultipartFile file) throws IOException {
        Long uid = userIdOf(username);
        if (uid == null) throw new RuntimeException("User not found");

        Map<String, Object> p = getProfileRowByUserId(uid);
        String userClub = p == null ? "" : nz(p.get("club_name")).trim();
        if (notBlank(userClub) && !Objects.equals(userClub, club)) {
            throw new RuntimeException("User does not belong to this club");
        }

        return uploadCertificate(token, club, eventId, username, file);
    }

    @GetMapping("/certificates/get")
    public ResponseEntity<?> getCertificate(@RequestParam String club,
                                            @RequestParam long eventId,
                                            @RequestParam String regNo) {
        Query q = em.createNativeQuery("""
            SELECT file_url
            FROM certificates
            WHERE club=? AND event_id=? AND reg_no=?
            ORDER BY updated_at DESC, id DESC
            LIMIT 1
        """);
        q.setParameter(1, club);
        q.setParameter(2, eventId);
        q.setParameter(3, regNo);

        List<?> rows = q.getResultList();
        if (rows.isEmpty()) throw new RuntimeException("Certificate not found");

        return ResponseEntity.ok(ok("fileUrl", nz(rows.get(0))));
    }

    // =========================================================
    // LIVESCORE
    // =========================================================
    @PostMapping("/admin/livescore/save")
    @Transactional
    public ResponseEntity<?> saveLiveScore(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                           @RequestBody Map<String, Object> body) {
        String club = nz(body.get("club")).trim();
        long eventId = Long.parseLong(nz(body.get("eventId")));
        Object ts = body.get("teamScores");

        requireClubAccess(token, club);

        if (!notBlank(club) || eventId <= 0 || !(ts instanceof List<?> list)) {
            throw new RuntimeException("club/eventId/teamScores required");
        }

        String eventClub = eventClubOf(eventId);
        if (!Objects.equals(eventClub, club)) {
            throw new RuntimeException("Event does not belong to selected club");
        }

        for (Object o : list) {
            if (!(o instanceof Map<?, ?> raw)) continue;
            int teamNo = toInt(raw.get("teamNo"), 0);
            int score = toInt(raw.get("score"), 0);
            if (teamNo <= 0) continue;

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

        return ResponseEntity.ok(ok("message", "Live score saved"));
    }


    @PostMapping("/admin/livescore/save-round")
    @Transactional
    public ResponseEntity<?> saveLiveScoreRound(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                                @RequestBody Map<String, Object> body) {
        return saveLiveScore(token, body);
    }

    @GetMapping("/livescore/get")
    public ResponseEntity<?> getLiveScore(@RequestParam String club,
                                          @RequestParam long eventId) {
        Query q = em.createNativeQuery("""
            SELECT team_no, score
            FROM livescores
            WHERE club=? AND event_id=?
            ORDER BY score DESC, team_no ASC
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

    // =========================================================
    // RECRUITMENTS
    // =========================================================
    @PostMapping("/recruitments/open")
    @Transactional
    public ResponseEntity<?> openRecruitment(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                             @RequestBody Map<String, Object> body) {
        String club = nz(body.get("club")).trim();
        String link = nz(body.get("link")).trim();
        requireClubAccess(token, club);

        Number count = (Number) em.createNativeQuery("SELECT COUNT(*) FROM recruitments WHERE club=?")
                .setParameter(1, club)
                .getSingleResult();

        if (count.longValue() > 0) {
            em.createNativeQuery("""
                UPDATE recruitments
                SET is_open=true, registration_link=?, updated_at=CURRENT_TIMESTAMP
                WHERE club=?
            """)
                    .setParameter(1, notBlank(link) ? link : null)
                    .setParameter(2, club)
                    .executeUpdate();
        } else {
            em.createNativeQuery("""
                INSERT INTO recruitments(
                    club, role_name, description, eligibility, skills_required,
                    last_date, is_open, registration_link, created_by, created_at, updated_at
                )
                VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
            """)
                    .setParameter(1, club)
                    .setParameter(2, "Club Member")
                    .setParameter(3, null)
                    .setParameter(4, null)
                    .setParameter(5, null)
                    .setParameter(6, null)
                    .setParameter(7, true)
                    .setParameter(8, notBlank(link) ? link : null)
                    .setParameter(9, requireTokenUser(token))
                    .executeUpdate();
        }

        return ResponseEntity.ok(ok("message", "Recruitment opened"));
    }

    @PostMapping("/recruitments/close")
    @Transactional
    public ResponseEntity<?> closeRecruitment(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                              @RequestBody Map<String, Object> body) {
        String club = nz(body.get("club")).trim();
        requireClubAccess(token, club);

        em.createNativeQuery("""
            UPDATE recruitments
            SET is_open=false, updated_at=CURRENT_TIMESTAMP
            WHERE club=?
        """)
                .setParameter(1, club)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Recruitment closed"));
    }

    @GetMapping("/recruitments/open")
    public ResponseEntity<?> openRecruitmentsPublic() {
        Query q = em.createNativeQuery("""
            SELECT club, role_name, description, eligibility, skills_required,
                   last_date, is_open, registration_link
            FROM recruitments
            WHERE is_open=true
            ORDER BY club ASC, id DESC
        """);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();

        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("club", nz(r[0]));
            m.put("roleName", nz(r[1]));
            m.put("description", nz(r[2]));
            m.put("eligibility", nz(r[3]));
            m.put("skillsRequired", nz(r[4]));
            m.put("lastDate", nz(r[5]));
            m.put("isOpen", toBool(r[6]));
            m.put("link", nz(r[7]));
            items.add(m);
        }

        return ResponseEntity.ok(ok("items", items));
    }

    @GetMapping("/recruitments")
    public ResponseEntity<?> allRecruitments(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                             @RequestParam(value = "club", required = false) String club) {
        String actor = requireTokenUser(token);
        String role = requireAdminOrCoordinator(token);

        if ("club_coordinator".equalsIgnoreCase(role)) {
            club = coordinatorClubOf(actor);
        }

        String sql = """
            SELECT id, club, role_name, description, eligibility, skills_required,
                   last_date, is_open, registration_link, created_by, created_at, updated_at
            FROM recruitments
        """;
        if (notBlank(club)) sql += " WHERE club=? ";
        sql += " ORDER BY updated_at DESC, id DESC";

        Query q = em.createNativeQuery(sql);
        if (notBlank(club)) q.setParameter(1, club);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();

        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", ((Number) r[0]).longValue());
            m.put("club", nz(r[1]));
            m.put("roleName", nz(r[2]));
            m.put("description", nz(r[3]));
            m.put("eligibility", nz(r[4]));
            m.put("skillsRequired", nz(r[5]));
            m.put("lastDate", nz(r[6]));
            m.put("isOpen", toBool(r[7]));
            m.put("link", nz(r[8]));
            m.put("createdBy", nz(r[9]));
            m.put("createdAt", nz(r[10]));
            m.put("updatedAt", nz(r[11]));
            m.put("open", toBool(r[7]));
            items.add(m);
        }

        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping("/recruitments/create")
    @Transactional
    public ResponseEntity<?> createRecruitment(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                               @RequestBody Map<String, Object> body) {
        String club = nz(body.get("club")).trim();
        requireClubAccess(token, club);

        String roleName = nz(body.get("roleName")).trim();
        String description = nz(body.get("description")).trim();
        String eligibility = nz(body.get("eligibility")).trim();
        String skillsRequired = nz(body.get("skillsRequired")).trim();
        String lastDate = nz(body.get("lastDate")).trim();
        boolean isOpen = body.get("isOpen") == null || toBool(body.get("isOpen"));
        String link = nz(body.get("link")).trim();
        String createdBy = requireTokenUser(token);

        if (!notBlank(club) || !notBlank(roleName)) {
            throw new RuntimeException("club/roleName required");
        }

        em.createNativeQuery("""
            INSERT INTO recruitments(
                club, role_name, description, eligibility, skills_required,
                last_date, is_open, registration_link, created_by, created_at, updated_at
            )
            VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
        """)
                .setParameter(1, club)
                .setParameter(2, roleName)
                .setParameter(3, notBlank(description) ? description : null)
                .setParameter(4, notBlank(eligibility) ? eligibility : null)
                .setParameter(5, notBlank(skillsRequired) ? skillsRequired : null)
                .setParameter(6, notBlank(lastDate) ? LocalDate.parse(lastDate) : null)
                .setParameter(7, isOpen)
                .setParameter(8, notBlank(link) ? link : null)
                .setParameter(9, createdBy)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Recruitment created"));
    }

    @PostMapping("/recruitments/apply")
    @Transactional
    public ResponseEntity<?> applyRecruitment(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                              @RequestBody Map<String, Object> body) {
        String username = requireTokenUser(token);

        String club = nz(body.get("club")).trim();
        String name = nz(body.get("name")).trim();
        String regNo = nz(body.get("regNo")).trim();
        String email = nz(body.get("email")).trim();
        String phone = nz(body.get("phone")).trim();
        String branch = nz(body.get("branch")).trim();
        String year = nz(body.get("year")).trim();
        String roleInterested = nz(body.get("roleInterested")).trim();
        if (!notBlank(roleInterested)) roleInterested = nz(body.get("role")).trim();
        String skills = nz(body.get("skills")).trim();
        String whyJoin = nz(body.get("whyJoin")).trim();

        if (!notBlank(club) || !notBlank(regNo)) {
            throw new RuntimeException("club/regNo required");
        }
        if (!Objects.equals(username, regNo)) {
            throw new RuntimeException("Logged-in username and register number must match");
        }

        Number count = (Number) em.createNativeQuery("""
            SELECT COUNT(*)
            FROM recruitment_applications
            WHERE club=? AND reg_no=?
        """)
                .setParameter(1, club)
                .setParameter(2, regNo)
                .getSingleResult();

        if (count.longValue() > 0) {
            em.createNativeQuery("""
                UPDATE recruitment_applications
                SET name=?, email=?, phone=?, branch=?, year=?, role_interested=?, skills=?, why_join=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE club=? AND reg_no=?
            """)
                    .setParameter(1, name)
                    .setParameter(2, email)
                    .setParameter(3, phone)
                    .setParameter(4, branch)
                    .setParameter(5, year)
                    .setParameter(6, notBlank(roleInterested) ? roleInterested : null)
                    .setParameter(7, skills)
                    .setParameter(8, whyJoin)
                    .setParameter(9, club)
                    .setParameter(10, regNo)
                    .executeUpdate();
        } else {
            em.createNativeQuery("""
                INSERT INTO recruitment_applications(
                    club, name, reg_no, email, phone, branch, year, role_interested, skills, why_join, status, created_at, updated_at
                )
                VALUES (?,?,?,?,?,?,?,?,?,?,'PENDING',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
            """)
                    .setParameter(1, club)
                    .setParameter(2, name)
                    .setParameter(3, regNo)
                    .setParameter(4, email)
                    .setParameter(5, phone)
                    .setParameter(6, branch)
                    .setParameter(7, year)
                    .setParameter(8, notBlank(roleInterested) ? roleInterested : null)
                    .setParameter(9, skills)
                    .setParameter(10, whyJoin)
                    .executeUpdate();
        }

        return ResponseEntity.ok(ok("message", "Application submitted"));
    }

    @GetMapping("/recruitments/applications")
    public ResponseEntity<?> listRecruitmentApplications(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                                         @RequestParam(value = "club", required = false) String club) {
        String actor = requireTokenUser(token);
        String role = requireAdminOrCoordinator(token);

        if ("club_coordinator".equalsIgnoreCase(role)) {
            club = coordinatorClubOf(actor);
        }

        String sql = """
            SELECT id, club, name, reg_no, email, phone, branch, year,
                   COALESCE(role_interested,''), skills, why_join, status, created_at, updated_at
            FROM recruitment_applications
        """;
        if (notBlank(club)) sql += " WHERE club=? ";
        sql += " ORDER BY updated_at DESC, id DESC";

        Query q = em.createNativeQuery(sql);
        if (notBlank(club)) q.setParameter(1, club);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", ((Number) r[0]).longValue());
            m.put("club", nz(r[1]));
            m.put("name", nz(r[2]));
            m.put("regNo", nz(r[3]));
            m.put("email", nz(r[4]));
            m.put("phone", nz(r[5]));
            m.put("branch", nz(r[6]));
            m.put("year", nz(r[7]));
            m.put("roleInterested", nz(r[8]));
            m.put("skills", nz(r[9]));
            m.put("whyJoin", nz(r[10]));
            m.put("status", nz(r[11]));
            m.put("createdAt", nz(r[12]));
            m.put("updatedAt", nz(r[13]));
            items.add(m);
        }

        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping("/recruitments/update-status")
    @Transactional
    public ResponseEntity<?> updateRecruitmentStatus(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                                     @RequestBody Map<String, Object> body) {
        String actor = requireTokenUser(token);
        String role = requireAdminOrCoordinator(token);

        long id = Long.parseLong(nz(body.get("id")));
        String status = nz(body.get("status")).trim().toUpperCase();
        if (!notBlank(status)) throw new RuntimeException("status required");

        Query q = em.createNativeQuery("""
            SELECT club, reg_no, name, email, COALESCE(role_interested,'')
            FROM recruitment_applications
            WHERE id=?
        """);
        q.setParameter(1, id);
        List<Object[]> rows = q.getResultList();
        if (rows.isEmpty()) throw new RuntimeException("Application not found");

        Object[] r = rows.get(0);
        String club = nz(r[0]);
        String regNo = nz(r[1]);
        String name = nz(r[2]);
        String email = nz(r[3]);
        String roleInterested = nz(r[4]);

        if ("club_coordinator".equalsIgnoreCase(role)) {
            String myClub = coordinatorClubOf(actor);
            if (!Objects.equals(myClub, club)) throw new RuntimeException("You can access only your own club");
        }

        em.createNativeQuery("""
            UPDATE recruitment_applications
            SET status=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """)
                .setParameter(1, status)
                .setParameter(2, id)
                .executeUpdate();

        if ("SELECTED".equals(status) || "APPROVED".equals(status)) {
            Number cmCount = (Number) em.createNativeQuery("""
                SELECT COUNT(*)
                FROM club_members
                WHERE username=? AND club=?
            """)
                    .setParameter(1, regNo)
                    .setParameter(2, club)
                    .getSingleResult();

            if (cmCount.longValue() > 0) {
                em.createNativeQuery("""
                    UPDATE club_members
                    SET role_name=?, updated_at=CURRENT_TIMESTAMP
                    WHERE username=? AND club=?
                """)
                        .setParameter(1, notBlank(roleInterested) ? roleInterested : "Club Member")
                        .setParameter(2, regNo)
                        .setParameter(3, club)
                        .executeUpdate();
            } else {
                em.createNativeQuery("""
                    INSERT INTO club_members(username, club, role_name, joined_at, updated_at)
                    VALUES (?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
                """)
                        .setParameter(1, regNo)
                        .setParameter(2, club)
                        .setParameter(3, notBlank(roleInterested) ? roleInterested : "Club Member")
                        .executeUpdate();
            }

            Long uid = userIdOf(regNo);
            if (uid != null) {
                Map<String, Object> p = getProfileRowByUserId(uid);
                upsertProfile(
                        uid,
                        p == null ? "" : nz(p.get("name")),
                        p == null ? "" : nz(p.get("phone")),
                        p == null ? "" : nz(p.get("email")),
                        p == null ? "" : nz(p.get("branch")),
                        p == null ? "" : nz(p.get("gender")),
                        p == null ? "" : nz(p.get("dob")),
                        p == null ? "" : nz(p.get("address")),
                        club,
                        notBlank(roleInterested) ? roleInterested : "Club Member"
                );
            }

            String toEmail = notBlank(email) ? email : getEmailForUser(regNo);
            if (notBlank(toEmail)) {
                sendCongratsMail(toEmail, notBlank(name) ? name : regNo, club, roleInterested);
            }
        }

        return ResponseEntity.ok(ok("message", "Application status updated"));
    }

    @GetMapping("/admin/club-students")
    public ResponseEntity<?> clubStudents(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                          @RequestParam String club) {
        requireClubAccess(token, club);

        Query q = em.createNativeQuery("""
            SELECT cm.username, COALESCE(up.name,''), cm.club, COALESCE(cm.role_name,''), COALESCE(cm.joined_at,'')
            FROM club_members cm
            LEFT JOIN users u ON u.username = cm.username
            LEFT JOIN user_profiles up ON up.user_id = u.id
            WHERE cm.club=?
            ORDER BY cm.username ASC
        """);
        q.setParameter(1, club);

        List<Object[]> rows = q.getResultList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object[] r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("username", nz(r[0]));
            m.put("name", nz(r[1]));
            m.put("club", nz(r[2]));
            m.put("role", nz(r[3]));
            m.put("joinedAt", nz(r[4]));
            items.add(m);
        }

        return ResponseEntity.ok(ok("items", items));
    }

    @PostMapping("/admin/club-students/delete")
    @Transactional
    public ResponseEntity<?> deleteClubStudent(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                               @RequestBody Map<String, Object> body) {
        String club = nz(body.get("club")).trim();
        String username = nz(body.get("username")).trim();
        requireClubAccess(token, club);
        if (!notBlank(club) || !notBlank(username)) throw new RuntimeException("club/username required");

        em.createNativeQuery("DELETE FROM club_members WHERE username=? AND club=?")
                .setParameter(1, username)
                .setParameter(2, club)
                .executeUpdate();

        Long uid = userIdOf(username);
        if (uid != null) {
            em.createNativeQuery("""
                UPDATE user_profiles
                SET club_name=NULL, club_role=NULL, club_joined_at=NULL
                WHERE user_id=? AND club_name=?
            """)
                    .setParameter(1, uid)
                    .setParameter(2, club)
                    .executeUpdate();
        }

        return ResponseEntity.ok(ok("message", "Club student removed"));
    }

    // =========================================================
    // OTP
    // =========================================================
    private String genOtp6() {
        int v = 100000 + random.nextInt(900000);
        return String.valueOf(v);
    }

    private void sendOtpMail(String to, String subject, String body) {
        if (mailSender == null) throw new RuntimeException("MailSender not configured");
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(body);
        mailSender.send(msg);
    }

    @PostMapping("/auth/forgot/send-otp")
    public ResponseEntity<?> forgotSendOtp(@RequestBody Map<String, Object> body) {
        String username = nz(body.get("username")).trim();
        if (!notBlank(username)) throw new RuntimeException("username required");
        if (!userExists(username)) throw new RuntimeException("User not found");

        String email = getEmailForUser(username);
        if (!notBlank(email)) throw new RuntimeException("No email found in profile. Complete profile first.");

        String otp = genOtp6();
        Instant exp = Instant.now().plusSeconds(5 * 60);

        otpService.createOtp(username, "FORGOT", otp, exp);
        sendOtpMail(email, "CMS OTP (Forgot Password)", "Your OTP is: " + otp + "\nValid for 5 minutes.");

        return ResponseEntity.ok(ok("message", "OTP sent"));
    }

    @PostMapping("/auth/forgot/verify-otp")
    public ResponseEntity<?> forgotVerifyOtp(@RequestBody Map<String, Object> body) {
        String username = nz(body.get("username")).trim();
        String otp = nz(body.get("otp")).trim();
        if (!notBlank(username) || !notBlank(otp)) throw new RuntimeException("username/otp required");

        Map<String, Object> row = otpService.getLatestOtp(username, "FORGOT");
        if (row == null) throw new RuntimeException("OTP not found");

        Instant exp = (Instant) row.get("expiresAt");
        if (Instant.now().isAfter(exp)) throw new RuntimeException("OTP expired");
        if (!Objects.equals(nz(row.get("otp")), otp)) throw new RuntimeException("Invalid OTP");

        otpService.markOtpVerified(((Number) row.get("id")).longValue());
        return ResponseEntity.ok(ok("message", "OTP verified"));
    }

    @PostMapping("/auth/forgot/reset")
    @Transactional
    public ResponseEntity<?> forgotReset(@RequestBody Map<String, Object> body) {
        String username = nz(body.get("username")).trim();
        String otp = nz(body.get("otp")).trim();
        String newPassword = nz(body.get("newPassword"));

        if (!notBlank(username) || !notBlank(otp) || !notBlank(newPassword)) {
            throw new RuntimeException("username/otp/newPassword required");
        }

        Map<String, Object> row = otpService.getLatestOtp(username, "FORGOT");
        if (row == null) throw new RuntimeException("OTP not found");

        Instant exp = (Instant) row.get("expiresAt");
        if (Instant.now().isAfter(exp)) throw new RuntimeException("OTP expired");
        if (!Objects.equals(nz(row.get("otp")), otp)) throw new RuntimeException("Invalid OTP");
        if (!Boolean.TRUE.equals(row.get("verified"))) throw new RuntimeException("OTP not verified");

        em.createNativeQuery("UPDATE users SET password=? WHERE username=?")
                .setParameter(1, newPassword)
                .setParameter(2, username)
                .executeUpdate();

        return ResponseEntity.ok(ok("message", "Password reset successful"));
    }

    @PostMapping("/me/profile/send-otp")
    public ResponseEntity<?> profileSendOtp(@RequestHeader(value = "X-Auth-Token", required = false) String token) {
        String username = requireTokenUser(token);

        String email = getEmailForUser(username);
        if (!notBlank(email)) throw new RuntimeException("No email in profile. Complete profile first.");

        String otp = genOtp6();
        Instant exp = Instant.now().plusSeconds(5 * 60);

        otpService.createOtp(username, "PROFILE_EDIT", otp, exp);
        sendOtpMail(email, "CMS OTP (Edit Profile)", "Your OTP is: " + otp + "\nValid for 5 minutes.");

        return ResponseEntity.ok(ok("message", "OTP sent"));
    }

    @PostMapping("/me/profile/verify-otp")
    public ResponseEntity<?> profileVerifyOtp(@RequestHeader(value = "X-Auth-Token", required = false) String token,
                                              @RequestBody Map<String, Object> body) {
        String username = requireTokenUser(token);
        String otp = nz(body.get("otp")).trim();
        if (!notBlank(otp)) throw new RuntimeException("otp required");

        Map<String, Object> row = otpService.getLatestOtp(username, "PROFILE_EDIT");
        if (row == null) throw new RuntimeException("OTP not found");

        Instant exp = (Instant) row.get("expiresAt");
        if (Instant.now().isAfter(exp)) throw new RuntimeException("OTP expired");
        if (!Objects.equals(nz(row.get("otp")), otp)) throw new RuntimeException("Invalid OTP");

        otpService.markOtpVerified(((Number) row.get("id")).longValue());
        return ResponseEntity.ok(ok("message", "OTP verified"));
    }
}

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
        Object verified = r[3];
        boolean v = verified instanceof Boolean b
                ? b
                : "1".equals(String.valueOf(verified)) || "true".equalsIgnoreCase(String.valueOf(verified));
        m.put("verified", v);
        return m;
    }

    @org.springframework.transaction.annotation.Transactional
    public void markOtpVerified(long otpId) {
        em.createNativeQuery("UPDATE otps SET verified=true WHERE id=?")
                .setParameter(1, otpId)
                .executeUpdate();
    }
}

@RestControllerAdvice
class GlobalHandler {
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> handleRuntime(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("ok", false, "message", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleEx(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("ok", false, "message", ex.getMessage()));
    }
}
