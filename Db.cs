using Npgsql;

namespace ClauseTracker;

/// <summary>PostgreSQL access. Only the server process ever talks to the database.</summary>
public static class Db
{
    static NpgsqlDataSource? source;

    public static void Configure(string connectionString) => source = NpgsqlDataSource.Create(connectionString);

    public static NpgsqlConnection Open() => (source ?? throw new InvalidOperationException("Database not configured")).OpenConnection();

    public static void Init()
    {
        using var c = Open();
        Exec(c, @"
CREATE TABLE IF NOT EXISTS users(
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  display_name TEXT NOT NULL,
  department TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('worker','leader')),
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  active BIGINT NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users (lower(username));

CREATE TABLE IF NOT EXISTS cases(
  id BIGSERIAL PRIMARY KEY,
  receipt TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by BIGINT NOT NULL REFERENCES users(id),
  state TEXT NOT NULL CHECK (state IN ('awaiting_Q1','awaiting_Q2','awaiting_Q3','in_process')),
  q1 TEXT, q2 TEXT, q3 TEXT,
  process TEXT,
  step BIGINT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','completed')),
  completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cases_receipt ON cases (lower(receipt));
CREATE INDEX IF NOT EXISTS ix_cases_creator ON cases(created_by);

CREATE TABLE IF NOT EXISTS step_logs(
  id BIGSERIAL PRIMARY KEY,
  case_id BIGINT NOT NULL REFERENCES cases(id),
  step_no BIGINT NOT NULL,
  department TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  completed_by BIGINT REFERENCES users(id),
  note TEXT,
  UNIQUE (case_id, step_no)
);

CREATE TABLE IF NOT EXISTS events(
  id BIGSERIAL PRIMARY KEY,
  case_id BIGINT NOT NULL REFERENCES cases(id),
  at TEXT NOT NULL,
  user_id BIGINT REFERENCES users(id),
  kind TEXT NOT NULL,
  text TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_case ON events(case_id);

CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);
");
    }

    /// <summary>Accepts either an Npgsql string or a postgres:// URL (as given by Neon, Render, Railway…).</summary>
    public static string NormalizeConnectionString(string s)
    {
        if (!s.StartsWith("postgres://") && !s.StartsWith("postgresql://")) return s;
        var u = new Uri(s);
        var user = u.UserInfo.Split(':', 2);
        var b = new NpgsqlConnectionStringBuilder
        {
            Host = u.Host, Port = u.Port > 0 ? u.Port : 5432, Database = u.AbsolutePath.TrimStart('/'),
            Username = Uri.UnescapeDataString(user[0]), Password = user.Length > 1 ? Uri.UnescapeDataString(user[1]) : "",
        };
        var q = System.Web.HttpUtility.ParseQueryString(u.Query);
        var ssl = q["sslmode"];
        if (ssl is "require" or "verify-ca" or "verify-full") b.SslMode = SslMode.Require;
        else if (ssl == "disable") b.SslMode = SslMode.Disable;
        return b.ConnectionString;
    }

    static NpgsqlCommand Cmd(NpgsqlConnection c, string sql, (string, object?)[] p)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (k, v) in p) cmd.Parameters.AddWithValue(k, v ?? DBNull.Value);
        return cmd;
    }

    public static void Exec(NpgsqlConnection c, string sql, params (string, object?)[] p)
    {
        using var cmd = Cmd(c, sql, p);
        cmd.ExecuteNonQuery();
    }

    public static List<Dictionary<string, object?>> Query(NpgsqlConnection c, string sql, params (string, object?)[] p)
    {
        using var cmd = Cmd(c, sql, p);
        using var r = cmd.ExecuteReader();
        var rows = new List<Dictionary<string, object?>>();
        while (r.Read())
        {
            var d = new Dictionary<string, object?>();
            for (int i = 0; i < r.FieldCount; i++) d[r.GetName(i)] = r.IsDBNull(i) ? null : r.GetValue(i);
            rows.Add(d);
        }
        return rows;
    }

    public static Dictionary<string, object?>? One(NpgsqlConnection c, string sql, params (string, object?)[] p) =>
        Query(c, sql, p).FirstOrDefault();

    public static long Insert(NpgsqlConnection c, string sql, params (string, object?)[] p)
    {
        using var cmd = Cmd(c, sql + " RETURNING id", p);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }
}
