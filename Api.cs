using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace ClauseTracker;

public class AppError : Exception { public AppError(string m) : base(m) { } }

/// <summary>Server-side login session; one per client token.</summary>
public class Session { public User? Me; public string Ip = ""; }

public record User(long Id, string Username, string Name, string Dept, string Role)
{
    public bool IsLeader => Role == "leader";
}

/// <summary>
/// All business rules and role enforcement live here (not in the UI), so a worker can never
/// obtain data or perform actions outside their role even if the UI were tampered with.
/// </summary>
public static class Api
{
    const string LeaderDept = "الإدارة";
    [ThreadStatic] static Session? cur;   // set for the duration of one synchronous Handle call
    static User? Me { get => cur!.Me; set => cur!.Me = value; }
    static readonly ConcurrentDictionary<string, (int Fails, DateTime Until)> loginFails = new();

    static string Now() => DateTime.UtcNow.ToString("o");
    static string Str(JsonElement a, string k) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "").Trim() : "";
    static long Lng(JsonElement a, string k) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.TryGetInt64(out var n) ? n : 0;
    static bool Bool(JsonElement a, string k) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;

    static User RequireUser() => Me ?? throw new AppError("يجب تسجيل الدخول أولًا.");
    static User RequireLeader() { var u = RequireUser(); if (!u.IsLeader) throw new AppError("هذه العملية متاحة للقائد فقط."); return u; }
    static User RequireWorker() { var u = RequireUser(); if (u.IsLeader) throw new AppError("القائد في وضع المشاهدة فقط ولا يمكنه تنفيذ هذه العملية."); return u; }

    public static object? Handle(string method, JsonElement a, Session session)
    {
        cur = session;
        try { return Dispatch(method, a); }
        finally { cur = null; }
    }

    static object? Dispatch(string method, JsonElement a)
    {
        switch (method)
        {
            case "boot": return Boot();
            case "setup": return Setup(a);
            case "login": return Login(a);
            case "logout": Me = null; return true;
            case "me": return Me == null ? null : UserDto(Me);
            case "processes": RequireLeader(); return ProcessesDto();
            case "createCase": return CreateCase(Str(a, "receipt"));
            case "tasks": return Tasks();
            case "answer": return Answer(Lng(a, "caseId"), Str(a, "question"), Str(a, "value"));
            case "completeStep": return CompleteStep(Lng(a, "caseId"), Str(a, "note"));
            case "dashboard": return Dashboard();
            case "caseDetail": return CaseDetail(Lng(a, "caseId"));
            case "users": return ListUsers();
            case "addUser": return AddUser(a);
            case "setUserActive": return SetUserActive(Lng(a, "userId"), Bool(a, "active"));
            case "resetPassword": return ResetPassword(Lng(a, "userId"), Str(a, "password"));
            case "exportCsv": return ExportCsv((int)Lng(a, "tz"));
            default: throw new AppError("طلب غير معروف.");
        }
    }

    // ---------- bootstrap & auth ----------

    /// <summary>On a public server, SETUP_KEY stops a stranger from creating the first (Leader) account.</summary>
    static string? SetupKey() => Environment.GetEnvironmentVariable("SETUP_KEY") is { Length: > 0 } k ? k : null;

    static object Boot()
    {
        long n = 0; string? err = null;
        try { using var c = Db.Open(); n = Convert.ToInt64(Db.One(c, "SELECT COUNT(*) n FROM users")!["n"]); }
        catch (Exception) { err = "الخادم متصل لكن قاعدة البيانات غير متاحة."; }
        return new { needsSetup = err == null && n == 0, setupKeyRequired = SetupKey() != null, dbError = err, user = Me == null ? null : UserDto(Me), departments = Workflow.Departments };
    }

    static object UserDto(User u) => new { id = u.Id, username = u.Username, name = u.Name, dept = u.Dept, role = u.Role };

    static (string hash, string salt) Hash(string pw, byte[]? salt = null)
    {
        salt ??= RandomNumberGenerator.GetBytes(16);
        var h = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(pw), salt, 100_000, HashAlgorithmName.SHA256, 32);
        return (Convert.ToBase64String(h), Convert.ToBase64String(salt));
    }

    static object Setup(JsonElement a)
    {
        using var c = Db.Open();
        if (Convert.ToInt64(Db.One(c, "SELECT COUNT(*) n FROM users")!["n"]) > 0) throw new AppError("تم الإعداد مسبقًا.");
        if (SetupKey() is { } key && !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Str(a, "setupKey")), Encoding.UTF8.GetBytes(key)))
            throw new AppError("مفتاح الإعداد غير صحيح.");
        var name = Str(a, "name"); var user = Str(a, "username"); var pw = Str(a, "password");
        ValidateUser(name, user, pw);
        var (h, s) = Hash(pw);
        Db.Exec(c, "INSERT INTO users(username,display_name,department,role,pw_hash,pw_salt,created_at) VALUES(@u,@n,@d,'leader',@h,@s,@t)",
            ("@u", user), ("@n", name), ("@d", LeaderDept), ("@h", h), ("@s", s), ("@t", Now()));
        return Login(a);
    }

    static void ValidateUser(string name, string user, string pw)
    {
        if (name.Length < 2) throw new AppError("أدخل الاسم الكامل.");
        if (user.Length < 3 || user.Any(char.IsWhiteSpace)) throw new AppError("اسم المستخدم لا يقل عن 3 أحرف وبدون مسافات.");
        if (pw.Length < 6) throw new AppError("كلمة المرور لا تقل عن 6 أحرف.");
    }

    static object Login(JsonElement a)
    {
        var uname = Str(a, "username").ToLowerInvariant() + "|" + cur!.Ip;   // lockout is per username + client address
        var lookupName = uname.Split('|')[0];
        if (loginFails.TryGetValue(uname, out var lf) && lf.Until > DateTime.UtcNow)
            throw new AppError("محاولات كثيرة خاطئة. حاول مرة أخرى بعد دقيقة.");
        using var c = Db.Open();
        var row = Db.One(c, "SELECT * FROM users WHERE lower(username)=lower(@u)", ("@u", lookupName));
        var pw = a.TryGetProperty("password", out var pv) ? pv.GetString() ?? "" : "";
        bool ok = false;
        if (row != null && (long)row["active"]! == 1)
        {
            var (h, _) = Hash(pw, Convert.FromBase64String((string)row["pw_salt"]!));
            ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(h), Encoding.UTF8.GetBytes((string)row["pw_hash"]!));
        }
        if (!ok)
        {
            var n = (loginFails.TryGetValue(uname, out var prev) ? prev.Fails : 0) + 1;
            loginFails[uname] = n >= 5 ? (0, DateTime.UtcNow.AddMinutes(1)) : (n, DateTime.MinValue);
            throw new AppError("اسم المستخدم أو كلمة المرور غير صحيحة.");
        }
        loginFails.TryRemove(uname, out _);
        Me = new User((long)row["id"]!, (string)row["username"]!, (string)row["display_name"]!, (string)row["department"]!, (string)row["role"]!);
        return UserDto(Me);
    }

    // ---------- helpers ----------

    static object ProcessesDto() => Workflow.Processes.Values.Select(p => new
    {
        code = p.Code, title = p.Title, trigger = p.Trigger, totalDays = p.TotalDays,
        steps = p.Steps.Select((s, i) => new { no = i + 1, dept = s.Dept, text = s.Text, days = s.Days }),
    });

    static void InTx(NpgsqlConnection c, Action body)
    {
        Db.Exec(c, "BEGIN");
        try { body(); Db.Exec(c, "COMMIT"); }
        catch (Exception e)
        {
            try { Db.Exec(c, "ROLLBACK"); } catch { }
            if (e is PostgresException { SqlState: "23505" }) throw new AppError("كود الإيصال هذا مسجل بالفعل.");
            throw;
        }
    }

    static void Event(NpgsqlConnection c, long caseId, long? userId, string kind, string? text) =>
        Db.Exec(c, "INSERT INTO events(case_id,at,user_id,kind,text) VALUES(@c,@t,@u,@k,@x)",
            ("@c", caseId), ("@t", Now()), ("@u", userId), ("@k", kind), ("@x", text));

    static string? PendingQuestion(string state) => state switch
    {
        "awaiting_Q1" => "Q1", "awaiting_Q2" => "Q2", "awaiting_Q3" => "Q3", _ => null
    };

    static object QuestionDto(string q) => new
    {
        key = q, text = Workflow.QuestionText[q],
        options = Workflow.QuestionOptions[q].Select(o => new { value = o.Value, label = o.Label }),
    };

    // ---------- worker actions ----------

    static object CreateCase(string receipt)
    {
        var u = RequireWorker();
        if (receipt.Length == 0) throw new AppError("أدخل كود الإيصال.");
        if (receipt.Length > 60) throw new AppError("كود الإيصال طويل جدًا.");
        using var c = Db.Open();
        long id = 0;
        InTx(c, () =>
        {
            if (Db.One(c, "SELECT 1 FROM cases WHERE lower(receipt)=lower(@r)", ("@r", receipt)) != null)
                throw new AppError("كود الإيصال هذا مسجل بالفعل.");
            id = Db.Insert(c, "INSERT INTO cases(receipt,created_at,created_by,state) VALUES(@r,@t,@u,'awaiting_Q1')",
                ("@r", receipt), ("@t", Now()), ("@u", u.Id));
            Event(c, id, u.Id, "created", receipt);
        });
        return new { caseId = id };
    }

    static object Tasks()
    {
        var u = RequireWorker();
        using var c = Db.Open();
        var questions = Db.Query(c, "SELECT id,receipt,state,created_at FROM cases WHERE created_by=@u AND status='open' AND state LIKE 'awaiting_%' ORDER BY id DESC", ("@u", u.Id))
            .Select(r => new { caseId = r["id"], receipt = r["receipt"], createdAt = r["created_at"], question = QuestionDto(PendingQuestion((string)r["state"]!)!) });

        var steps = Db.Query(c, @"SELECT c.id,c.receipt,c.process,c.step,s.started_at FROM cases c
            JOIN step_logs s ON s.case_id=c.id AND s.step_no=c.step
            WHERE c.state='in_process' AND c.status='open' AND s.completed_at IS NULL AND s.department=@d ORDER BY s.started_at", ("@d", u.Dept))
            .Select(r =>
            {
                var st = Workflow.Processes[(string)r["process"]!].Steps[(int)(long)r["step"]! - 1];
                return new { caseId = r["id"], receipt = r["receipt"], startedAt = r["started_at"], text = st.Text, days = st.Days };
            });
        return new { questions, steps };
    }

    static object Answer(long caseId, string question, string value)
    {
        var u = RequireWorker();
        using var c = Db.Open();
        InTx(c, () =>
        {
            var cs = Db.One(c, "SELECT * FROM cases WHERE id=@i FOR UPDATE", ("@i", caseId)) ?? throw new AppError("الحالة غير موجودة.");
            if ((long)cs["created_by"]! != u.Id) throw new AppError("لا يمكنك الإجابة عن هذه الحالة.");
            var q = PendingQuestion((string)cs["state"]!) ?? throw new AppError("لا يوجد سؤال معلق لهذه الحالة.");
            // The client names the question it is answering; a stale answer must never land on the next question.
            if (q != question) throw new AppError("تمت الإجابة عن هذا السؤال بالفعل. حدّث القائمة.");
            if (!Workflow.QuestionOptions[q].Any(o => o.Value == value)) throw new AppError("إجابة غير صالحة.");
            var col = q.ToLower();
            Db.Exec(c, $"UPDATE cases SET {col}=@v WHERE id=@i", ("@v", value), ("@i", caseId));
            Event(c, caseId, u.Id, col, value);

            switch (q, value)
            {
                case ("Q1", "no"): Assign(c, caseId, "C1"); break;
                case ("Q1", "yes"): Db.Exec(c, "UPDATE cases SET state='awaiting_Q2' WHERE id=@i", ("@i", caseId)); break;
                case ("Q2", "no"): Assign(c, caseId, "C5"); break;
                case ("Q2", "yes"): Db.Exec(c, "UPDATE cases SET state='awaiting_Q3' WHERE id=@i", ("@i", caseId)); break;
                case ("Q3", "above25"): Assign(c, caseId, "C4"); break;
                case ("Q3", "upto25"): Assign(c, caseId, "C3"); break;
                case ("Q3", "notexceed"): Assign(c, caseId, "C2"); break;
            }
        });
        return true;
    }

    static void Assign(NpgsqlConnection c, long caseId, string proc)
    {
        Db.Exec(c, "UPDATE cases SET state='in_process', process=@p, step=1 WHERE id=@i", ("@p", proc), ("@i", caseId));
        Event(c, caseId, null, "assigned", proc);
        StartStep(c, caseId, proc, 1);
    }

    static void StartStep(NpgsqlConnection c, long caseId, string proc, int step) =>
        Db.Exec(c, "INSERT INTO step_logs(case_id,step_no,department,started_at) VALUES(@c,@n,@d,@t)",
            ("@c", caseId), ("@n", step), ("@d", Workflow.Processes[proc].Steps[step - 1].Dept), ("@t", Now()));

    static object CompleteStep(long caseId, string note)
    {
        var u = RequireWorker();
        if (note.Length > 500) throw new AppError("الملاحظة طويلة جدًا (500 حرف كحد أقصى).");
        using var c = Db.Open();
        InTx(c, () =>
        {
            var cs = Db.One(c, "SELECT * FROM cases WHERE id=@i FOR UPDATE", ("@i", caseId)) ?? throw new AppError("الحالة غير موجودة.");
            if ((string)cs["state"]! != "in_process" || (string)cs["status"]! != "open") throw new AppError("لا توجد خطوة نشطة لهذه الحالة.");
            var proc = (string)cs["process"]!; var step = (int)(long)cs["step"]!;
            var def = Workflow.Processes[proc];
            if (def.Steps[step - 1].Dept != u.Dept) throw new AppError("هذه الخطوة ليست تابعة لإدارتك.");
            var log = Db.One(c, "SELECT id FROM step_logs WHERE case_id=@i AND step_no=@n AND completed_at IS NULL", ("@i", caseId), ("@n", step))
                ?? throw new AppError("تم إنجاز هذه الخطوة بالفعل.");
            Db.Exec(c, "UPDATE step_logs SET completed_at=@t, completed_by=@u, note=@n WHERE id=@l",
                ("@t", Now()), ("@u", u.Id), ("@n", note.Length == 0 ? null : note), ("@l", log["id"]));
            Event(c, caseId, u.Id, "step_done", $"{step}");
            if (step == def.Steps.Length)
            {
                Db.Exec(c, "UPDATE cases SET status='completed', completed_at=@t WHERE id=@i", ("@t", Now()), ("@i", caseId));
                Event(c, caseId, u.Id, "completed", proc);
            }
            else
            {
                Db.Exec(c, "UPDATE cases SET step=@s WHERE id=@i", ("@s", step + 1), ("@i", caseId));
                StartStep(c, caseId, proc, step + 1);
            }
        });
        return true;
    }

    // ---------- leader views ----------

    static Dictionary<string, object?> CaseRow(Dictionary<string, object?> r)
    {
        var state = (string)r["state"]!; var status = (string)r["status"]!;
        string? proc = r["process"] as string; long? step = r["step"] as long?;
        string? dept = null, stepText = null; int? days = null, stepCount = null; bool overdue = false; string? due = null;
        if (proc != null && step != null)
        {
            var def = Workflow.Processes[proc]; var st = def.Steps[(int)step - 1];
            dept = st.Dept; stepText = st.Text; days = st.Days; stepCount = def.Steps.Length;
            if (status == "open" && r["step_started"] is string ss)
            {
                var dueAt = DateTime.Parse(ss, null, System.Globalization.DateTimeStyles.RoundtripKind).AddDays(st.Days);
                due = dueAt.ToString("o"); overdue = DateTime.UtcNow > dueAt;
            }
        }
        return new()
        {
            ["id"] = r["id"], ["receipt"] = r["receipt"], ["createdAt"] = r["created_at"], ["creator"] = r["creator"],
            ["state"] = state, ["status"] = status, ["completedAt"] = r["completed_at"],
            ["process"] = proc, ["step"] = step, ["stepCount"] = stepCount, ["dept"] = dept, ["stepText"] = stepText,
            ["stepDays"] = days, ["stepStartedAt"] = r["step_started"], ["dueAt"] = due, ["overdue"] = overdue,
            ["pendingQuestion"] = PendingQuestion(state) is { } q ? Workflow.QuestionText[q] : null,
        };
    }

    static List<Dictionary<string, object?>> AllCases(NpgsqlConnection c) =>
        Db.Query(c, @"SELECT c.*, u.display_name AS creator,
            (SELECT started_at FROM step_logs s WHERE s.case_id=c.id AND s.step_no=c.step) AS step_started
            FROM cases c JOIN users u ON u.id=c.created_by ORDER BY c.id DESC").Select(CaseRow).ToList();

    static object Dashboard()
    {
        RequireLeader();
        using var c = Db.Open();
        var cases = AllCases(c);
        var open = cases.Where(x => (string)x["status"]! == "open").ToList();
        return new
        {
            cases,
            totals = new
            {
                open = open.Count,
                questions = open.Count(x => (string)x["state"]! != "in_process"),
                overdue = open.Count(x => (bool)x["overdue"]!),
                completed = cases.Count - open.Count,
            },
            byDept = Workflow.Departments.Select(d => new { dept = d, count = open.Count(x => (string?)x["dept"] == d) }),
        };
    }

    static object CaseDetail(long id)
    {
        RequireLeader();
        using var c = Db.Open();
        var r = Db.One(c, @"SELECT c.*, u.display_name AS creator,
            (SELECT started_at FROM step_logs s WHERE s.case_id=c.id AND s.step_no=c.step) AS step_started
            FROM cases c JOIN users u ON u.id=c.created_by WHERE c.id=@i", ("@i", id)) ?? throw new AppError("الحالة غير موجودة.");
        var cv = CaseRow(r);
        var answers = Db.Query(c, @"SELECT e.kind,e.text,e.at,u.display_name AS by_name FROM events e LEFT JOIN users u ON u.id=e.user_id
            WHERE e.case_id=@i AND e.kind IN ('q1','q2','q3') ORDER BY e.id", ("@i", id))
            .Select(e => { var q = ((string)e["kind"]!).ToUpperInvariant(); return new { question = Workflow.QuestionText[q], answer = Workflow.AnswerLabel(q, (string)e["text"]!), at = e["at"], by = e["by_name"] }; });

        object? steps = null;
        if (cv["process"] is string proc)
        {
            var logs = Db.Query(c, @"SELECT s.*, u.display_name AS by_name FROM step_logs s LEFT JOIN users u ON u.id=s.completed_by WHERE s.case_id=@i", ("@i", id));
            var def = Workflow.Processes[proc];
            steps = def.Steps.Select((st, i) =>
            {
                var l = logs.FirstOrDefault(x => (long)x["step_no"]! == i + 1);
                string? due = null;
                if (l != null) due = DateTime.Parse((string)l["started_at"]!, null, System.Globalization.DateTimeStyles.RoundtripKind).AddDays(st.Days).ToString("o");
                return new
                {
                    no = i + 1, dept = st.Dept, text = st.Text, days = st.Days,
                    startedAt = l?["started_at"], completedAt = l?["completed_at"], by = l?["by_name"], note = l?["note"], dueAt = due,
                };
            });
            cv["processTitle"] = def.Title; cv["totalDays"] = def.TotalDays;
        }
        return new { info = cv, answers, steps };
    }

    static string Csv(string? s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";

    static object ExportCsv(int tzMinutes)
    {
        RequireLeader();
        using var c = Db.Open();
        var sb = new StringBuilder();
        sb.AppendLine("كود الإيصال,العملية,الحالة,الخطوة الحالية,الإدارة الحالية,تاريخ الإنشاء,تاريخ الإكمال,متأخر,المدخِل");
        foreach (var r in AllCases(c))
        {
            var state = (string)r["state"]! == "in_process" ? "قيد التنفيذ" : (string)r["status"]! == "completed" ? "مكتملة" : "في مرحلة الأسئلة";
            if ((string)r["status"]! == "completed") state = "مكتملة";
            sb.AppendLine(string.Join(",", Csv((string)r["receipt"]!), Csv(r["process"] as string), Csv(state),
                Csv(r["step"] == null ? "" : $"{r["step"]}/{r["stepCount"]}"), Csv(r["dept"] as string),
                Csv(Local(r["createdAt"], tzMinutes)), Csv(Local(r["completedAt"], tzMinutes)), Csv((bool)r["overdue"]! ? "نعم" : "لا"), Csv((string)r["creator"]!)));
        }
        return new { fileName = $"cases-{DateTime.UtcNow.AddMinutes(tzMinutes):yyyy-MM-dd}.csv", csv = sb.ToString() };
    }

    static string Local(object? iso, int tz) => iso is string s ? DateTime.Parse(s, null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime().AddMinutes(tz).ToString("yyyy-MM-dd HH:mm") : "";

    // ---------- user administration (leader) ----------

    static object ListUsers()
    {
        RequireLeader();
        using var c = Db.Open();
        return Db.Query(c, "SELECT id,username,display_name,department,role,active FROM users ORDER BY role DESC, department, display_name")
            .Select(r => new { id = r["id"], username = r["username"], name = r["display_name"], dept = r["department"], role = r["role"], active = (long)r["active"]! == 1 });
    }

    static object AddUser(JsonElement a)
    {
        RequireLeader();
        var name = Str(a, "name"); var user = Str(a, "username"); var pw = Str(a, "password");
        var dept = Str(a, "dept"); var role = Str(a, "role") == "leader" ? "leader" : "worker";
        ValidateUser(name, user, pw);
        if (role == "leader") dept = LeaderDept;
        else if (!Workflow.Departments.Contains(dept)) throw new AppError("اختر الإدارة.");
        using var c = Db.Open();
        if (Db.One(c, "SELECT 1 FROM users WHERE lower(username)=lower(@u)", ("@u", user)) != null) throw new AppError("اسم المستخدم مستخدم بالفعل.");
        var (h, s) = Hash(pw);
        Db.Exec(c, "INSERT INTO users(username,display_name,department,role,pw_hash,pw_salt,created_at) VALUES(@u,@n,@d,@r,@h,@s,@t)",
            ("@u", user), ("@n", name), ("@d", dept), ("@r", role), ("@h", h), ("@s", s), ("@t", Now()));
        return true;
    }

    static object SetUserActive(long id, bool active)
    {
        var me = RequireLeader();
        if (id == me.Id) throw new AppError("لا يمكنك تعطيل حسابك الحالي.");
        using var c = Db.Open();
        Db.Exec(c, "UPDATE users SET active=@a WHERE id=@i", ("@a", active ? 1 : 0), ("@i", id));
        return true;
    }

    static object ResetPassword(long id, string pw)
    {
        RequireLeader();
        if (pw.Length < 6) throw new AppError("كلمة المرور لا تقل عن 6 أحرف.");
        var (h, s) = Hash(pw);
        using var c = Db.Open();
        Db.Exec(c, "UPDATE users SET pw_hash=@h, pw_salt=@s WHERE id=@i", ("@h", h), ("@s", s), ("@i", id));
        return true;
    }
}