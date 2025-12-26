using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;

public class DBManager
{
    private SqliteConnection? _connection;
    private bool _isConnected = false;

    public bool IsConnected => _isConnected;

    public bool ConnectToDB(string path)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
            
            _connection = new SqliteConnection($"Data Source={path}");
            _connection.Open();
            
            CreateTables();
            _isConnected = true;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Database connection error: {ex.Message}");
            return false;
        }
    }

    private void CreateTables()
    {
        if (_connection == null) return;
        string usersTableSql = @"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )";

        using (var cmd = new SqliteCommand(usersTableSql, _connection))
        {
            cmd.ExecuteNonQuery();
        }
    }

    private string HashPassword(string password)
    {
        using (var algorithm = SHA256.Create())
        {
            var bytesHash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytesHash);
        }
    }

    public User? RegisterUser(string login, string password)
    {
        if (!_isConnected || _connection == null)
        {
            return null;
        }

        try
        {
            string sql = @"
                INSERT INTO users (login, password_hash) 
                VALUES (@login, @passwordHash)
                RETURNING id, login, password_hash, created_at";

            using var cmd = new SqliteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@login", login);
            cmd.Parameters.AddWithValue("@passwordHash", HashPassword(password));

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Id = reader.GetInt32(0),
                    Login = reader.GetString(1),
                    PasswordHash = reader.GetString(2),
                    CreatedAt = reader.GetDateTime(3)
                };
            }
            return null;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error adding user: {ex.Message}");
            return null;
        }
    }

    public User? AuthenticateUser(string login, string password)
    {
        if (!_isConnected || _connection == null)
        {
            return null;
        }

        try
        {
            string sql = @"
                SELECT id, login, password_hash, created_at 
                FROM users 
                WHERE login = @login AND password_hash = @passwordHash";

            using var cmd = new SqliteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@login", login);
            cmd.Parameters.AddWithValue("@passwordHash", HashPassword(password));

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Id = reader.GetInt32(0),
                    Login = reader.GetString(1),
                    PasswordHash = reader.GetString(2),
                    CreatedAt = reader.GetDateTime(3)
                };
            }
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error authenticating user: {ex.Message}");
            return null;
        }
    }

    public User? GetUserById(int id)
    {
        if (!_isConnected || _connection == null) return null;

        try
        {
            string sql = "SELECT id, login, password_hash, created_at FROM users WHERE id = @id";
            using var cmd = new SqliteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@id", id);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Id = reader.GetInt32(0),
                    Login = reader.GetString(1),
                    PasswordHash = reader.GetString(2),
                    CreatedAt = reader.GetDateTime(3)
                };
            }
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting user: {ex.Message}");
            return null;
        }
    }

    public bool ChangePassword(int userId, string oldPassword, string newPassword)
    {
        if (!_isConnected || _connection == null) return false;

        var user = GetUserById(userId);
        if (user == null) return false;

        if (HashPassword(oldPassword) != user.PasswordHash)
            return false;

        try
        {
            string sql = "UPDATE users SET password_hash = @newHash WHERE id = @userId";
            using var cmd = new SqliteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@newHash", HashPassword(newPassword));
            cmd.Parameters.AddWithValue("@userId", userId);

            return cmd.ExecuteNonQuery() > 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error changing password: {ex.Message}");
            return false;
        }
    }

    public bool DeleteUser(int userId)
    {
        if (!_isConnected || _connection == null) return false;

        try
        {
            string sql = "DELETE FROM users WHERE id = @userId";
            using var cmd = new SqliteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@userId", userId);

            return cmd.ExecuteNonQuery() > 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error deleting user: {ex.Message}");
            return false;
        }
    }

    public void Disconnect()
    {
        _connection?.Close();
        _connection?.Dispose();
        _connection = null;
        _isConnected = false;
    }
}

public class HillCipherService
{
    private const int MOD = 37; // 26 букв + 10 цифр + пробел
    private readonly int[] _defaultKey = { 6, 24, 13, 16 };

    public HillCipherResult Encrypt(string text, string? key = null)
    {
        int[] keyMatrix = GetKeyMatrix(key);
        text = PrepareText(text);
        
        var result = new StringBuilder();
        for (int i = 0; i < text.Length; i += 2)
        {
            int c1 = CharToNum(text[i]);
            int c2 = CharToNum(text[i + 1]);
            
            int r1 = (keyMatrix[0] * c1 + keyMatrix[1] * c2) % MOD;
            int r2 = (keyMatrix[2] * c1 + keyMatrix[3] * c2) % MOD;
            
            result.Append(NumToChar(r1));
            result.Append(NumToChar(r2));
        }
        
        return new HillCipherResult(result.ToString(), string.Join(",", keyMatrix));
    }

    public HillCipherResult Decrypt(string ciphertext, string? key = null)
    {
        int[] keyMatrix = GetKeyMatrix(key);
        int[] inverseKey = GetInverseMatrix(keyMatrix);
        
        ciphertext = PrepareText(ciphertext);
        
        var result = new StringBuilder();
        for (int i = 0; i < ciphertext.Length; i += 2)
        {
            int c1 = CharToNum(ciphertext[i]);
            int c2 = CharToNum(ciphertext[i + 1]);
            
            int r1 = (inverseKey[0] * c1 + inverseKey[1] * c2) % MOD;
            int r2 = (inverseKey[2] * c1 + inverseKey[3] * c2) % MOD;
            
            if (r1 < 0) r1 += MOD;
            if (r2 < 0) r2 += MOD;
            
            result.Append(NumToChar(r1));
            result.Append(NumToChar(r2));
        }
        
        string decrypted = result.ToString().TrimEnd('X');
        return new HillCipherResult(decrypted);
    }

    private int[] GetKeyMatrix(string? key)
    {
        if (!string.IsNullOrEmpty(key))
        {
            return key.Split(',').Select(int.Parse).ToArray();
        }
        return _defaultKey;
    }

    private string PrepareText(string text)
    {
        text = text.ToUpper();
        var clean = new StringBuilder();
        
        foreach (char c in text)
        {
            if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ')
                clean.Append(c);
        }
        
        if (clean.Length % 2 != 0)
            clean.Append('X');
            
        return clean.ToString();
    }

    private int CharToNum(char c)
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= '0' && c <= '9') return 26 + (c - '0');
        return 36; // пробел
    }

    private char NumToChar(int n)
    {
        n %= MOD;
        if (n < 26) return (char)('A' + n);
        if (n < 36) return (char)('0' + (n - 26));
        return ' ';
    }

    private int[] GetInverseMatrix(int[] key)
    {
        int det = (key[0] * key[3] - key[1] * key[2]) % MOD;
        det = (det + MOD) % MOD;
        
        int detInv = 1;
        while ((det * detInv) % MOD != 1) detInv++;
        
        return new int[]
        {
            (key[3] * detInv) % MOD,
            (-key[1] * detInv) % MOD,
            (-key[2] * detInv) % MOD,
            (key[0] * detInv) % MOD
        };
    }
}