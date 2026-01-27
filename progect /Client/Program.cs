using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite; 

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Hill Cipher Client ===");
        Console.WriteLine("Сервер должен быть запущен на http://localhost:5014");
        Console.WriteLine("Нажмите любую клавишу для запуска...");
        Console.ReadKey();
        
        AuthVal validator = new AuthVal();
        UserRepo userRepo = new UserRepo();
        ActLog actionLogger = new ActLog();
        
        ApiH apiHandler = new ApiH("http://localhost:5014");
        
        User? activeUser = null;

        while (true)
        {
            Console.Clear();
            Console.WriteLine("========== Hill Cipher Client ==========");
            Console.WriteLine(activeUser == null ? "Пользователь: Не вошел" : $"Пользователь: {activeUser.Username}");
            Console.WriteLine($"Сервер: http://localhost:5014");
            Console.WriteLine("========================================");
            Console.WriteLine("1 – Регистрация");
            Console.WriteLine("2 – Вход в аккаунт");
            Console.WriteLine("3 – Проверить текущего пользователя");
            Console.WriteLine("4 – Шифровать текст");
            Console.WriteLine("5 – Дешифровать текст");
            Console.WriteLine("6 – История операций");
            Console.WriteLine("7 – Сменить пароль");
            Console.WriteLine("8 – Удалить аккаунт");
            Console.WriteLine("9 – Выход из аккаунта");
            Console.WriteLine("10 – Справка");
            Console.WriteLine("11 – Проверить соединение с сервером");
            Console.WriteLine("0 – Закрыть программу");
            Console.WriteLine("========================================");
            Console.Write("Введите номер команды: ");
            string cmd = Console.ReadLine() ?? "";

            switch (cmd)
            {
                case "1":
                    await HandleRegistration(validator, apiHandler, userRepo);
                    break;

                case "2":
                    activeUser = await HandleLogin(validator, apiHandler, userRepo, activeUser);
                    break;

                case "3":
                    await HandleCheckUser(apiHandler, activeUser);
                    break;

                case "4":
                    await HandleEncrypt(apiHandler, actionLogger, activeUser, validator);
                    break;

                case "5":
                    await HandleDecrypt(apiHandler, actionLogger, activeUser, validator);
                    break;

                case "6":
                    HandleHistory(actionLogger, activeUser);
                    break;

                case "7":
                    activeUser = await HandleChangePassword(validator, apiHandler, activeUser);
                    break;

                case "8":
                    activeUser = await HandleDeleteAccount(apiHandler, userRepo, activeUser);
                    break;

                case "9":
                    activeUser = await HandleLogout(apiHandler, activeUser);
                    break;

                case "10":
                    ShowHelp();
                    break;

                case "11":
                    await TestConnection(apiHandler);
                    break;

                case "0":
                    Console.WriteLine("Выход из программы...");
                    return;

                default:
                    Console.WriteLine("Неверная команда.");
                    break;
            }

            if (cmd != "0")
            {
                Console.WriteLine("\nНажмите любую клавишу для продолжения...");
                Console.ReadKey();
            }
        }
    }

    private static async Task TestConnection(ApiH apiHandler)
    {
        Console.WriteLine("Проверка соединения с сервером...");
        try
        {
            using (var testClient = new HttpClient())
            {
                testClient.Timeout = TimeSpan.FromSeconds(5);
                var response = await testClient.GetAsync("http://localhost:5014");
                
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("✓ Сервер доступен!");
                    var content = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Ответ сервера: {content}");
                }
                else
                {
                    Console.WriteLine($"✗ Сервер отвечает с ошибкой: {response.StatusCode}");
                }
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"✗ Ошибка сети: {ex.Message}");
            Console.WriteLine("Убедитесь, что сервер запущен на http://localhost:5014");
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("✗ Таймаут соединения. Сервер не отвечает.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка: {ex.Message}");
        }
    }

    private static async Task HandleRegistration(AuthVal validator, ApiH apiHandler, UserRepo userRepo)
    {
        Console.Write("Логин: ");
        string regLogin = Console.ReadLine() ?? "";
        Console.Write("Пароль: ");
        string regPass = Console.ReadLine() ?? "";

        if (!validator.ValLogin(regLogin))
        {
            Console.WriteLine("Логин не подходит! (4-20 символов, буквы/цифры/_)");
            return;
        }

        if (!validator.ValPass(regPass))
        {
            Console.WriteLine("Пароль не подходит! (≥8 символов, минимум 2 цифры, буквы)");
            return;
        }

        Console.WriteLine("Отправка запроса на регистрацию...");
        var regResult = await apiHandler.Signup(regLogin, regPass);
        
        if (regResult != null && regResult.success)
        {
            var userLocal = userRepo.InsUsr(regLogin, regResult.user?.Id ?? 0);
            if (userLocal != null)
                Console.WriteLine($"✓ Пользователь {regLogin} зарегистрирован. Теперь войдите через пункт 2.");
            else
                Console.WriteLine("✗ Ошибка локального сохранения пользователя.");
        }
        else
        {
            Console.WriteLine("✗ Ошибка регистрации. Проверьте, запущен ли сервер.");
            Console.WriteLine($"Сообщение от сервера: {regResult?.message ?? "Нет ответа"}");
        }
    }

    private static async Task<User?> HandleLogin(AuthVal validator, ApiH apiHandler, UserRepo userRepo, User? activeUser)
    {
        if (activeUser != null)
        {
            Console.WriteLine("Сначала выйдите из аккаунта!");
            return activeUser;
        }

        Console.Write("Логин: ");
        string loginInput = Console.ReadLine() ?? "";
        Console.Write("Пароль: ");
        string passInput = Console.ReadLine() ?? "";

        Console.WriteLine("Попытка входа...");
        var loginResult = await apiHandler.Login(loginInput, passInput);
        
        if (loginResult != null && loginResult.success)
        {
            activeUser = userRepo.FindByNm(loginInput)
                         ?? userRepo.InsUsr(loginInput, loginResult.user?.Id ?? 0);
            if (activeUser != null)
                Console.WriteLine($"✓ Привет, {activeUser.Username}!");
            else
                Console.WriteLine("✗ Ошибка локального сохранения пользователя.");
        }
        else
        {
            Console.WriteLine("✗ Ошибка входа. Проверьте логин/пароль.");
            Console.WriteLine($"Сообщение от сервера: {loginResult?.message ?? "Нет ответа"}");
        }
        
        return activeUser;
    }

    private static async Task HandleCheckUser(ApiH apiHandler, User? activeUser)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Сначала войдите!");
            return;
        }

        Console.WriteLine("Проверка пользователя...");
        var checkResult = await apiHandler.CheckUser();
        
        if (checkResult != null)
        {
            Console.WriteLine($"✓ Информация о пользователе:");
            Console.WriteLine($"  ID: {checkResult.Id}");
            Console.WriteLine($"  Логин: {checkResult.Login}");
            Console.WriteLine($"  Создан: {checkResult.CreatedAt}");
        }
        else
        {
            Console.WriteLine("✗ Ошибка проверки пользователя.");
        }
    }

    private static async Task HandleEncrypt(ApiH apiHandler, ActLog actionLogger, User? activeUser, AuthVal validator)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Сначала войдите!");
            return;
        }

        Console.Write("Введите текст для шифрования (оставьте пустым для 'Hello World'): ");
        string encText = Console.ReadLine() ?? "";
        
        Console.Write("Введите ключ (формат: 1,2,3,4, оставьте пустым для ключа по умолчанию): ");
        string encKey = Console.ReadLine() ?? "";
        
        if (!string.IsNullOrEmpty(encKey) && !validator.ValKey(encKey))
        {
            Console.WriteLine("Некорректный формат ключа!");
            return;
        }

        Console.WriteLine("Шифрование...");
        var encryptResult = await apiHandler.Encrypt(encText, string.IsNullOrEmpty(encKey) ? null : encKey);
        
        if (encryptResult != null)
        {
            Console.WriteLine("\n=== Результат шифрования ===");
            Console.WriteLine($"Исходный текст: {encText}");
            Console.WriteLine($"Зашифрованный текст: {encryptResult.Result}");
            Console.WriteLine($"Использованный ключ: {encryptResult.Key}");
            
            actionLogger.Add(new ActionRecord
            {
                UserOwner = activeUser.Uid,
                ActionType = "ENCRYPT",
                Text = 0,
                ActionResult = $"Text: {encText}, Encrypted: {encryptResult.Result}, Key: {encryptResult.Key}"
            });
        }
        else
        {
            Console.WriteLine("✗ Ошибка шифрования.");
        }
    }

    private static async Task HandleDecrypt(ApiH apiHandler, ActLog actionLogger, User? activeUser, AuthVal validator)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Сначала войдите!");
            return;
        }

        Console.Write("Введите зашифрованный текст: ");
        string decText = Console.ReadLine() ?? "";
        
        if (string.IsNullOrEmpty(decText))
        {
            Console.WriteLine("Текст не может быть пустым!");
            return;
        }
        
        Console.Write("Введите ключ (формат: 1,2,3,4, оставьте пустым для ключа по умолчанию): ");
        string decKey = Console.ReadLine() ?? "";
        
        if (!string.IsNullOrEmpty(decKey) && !validator.ValKey(decKey))
        {
            Console.WriteLine("Некорректный формат ключа!");
            return;
        }

        Console.WriteLine("Дешифрование...");
        var decryptResult = await apiHandler.Decrypt(decText, string.IsNullOrEmpty(decKey) ? null : decKey);
        
        if (decryptResult != null)
        {
            Console.WriteLine("\n=== Результат дешифрования ===");
            Console.WriteLine($"Зашифрованный текст: {decText}");
            Console.WriteLine($"Расшифрованный текст: {decryptResult.Result}");
            Console.WriteLine($"Использованный ключ: {decryptResult.Key ?? "default"}");
            
            actionLogger.Add(new ActionRecord
            {
                UserOwner = activeUser.Uid,
                ActionType = "DECRYPT",
                Text = 0,
                ActionResult = $"Ciphertext: {decText}, Decrypted: {decryptResult.Result}, Key: {decryptResult.Key}"
            });
        }
        else
        {
            Console.WriteLine("✗ Ошибка дешифрования.");
        }
    }

    private static void HandleHistory(ActLog actionLogger, User? activeUser)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Сначала войдите!");
            return;
        }

        var logs = actionLogger.GetActions(activeUser.Uid);
        if (logs.Count == 0)
            Console.WriteLine("История операций пуста.");
        else
        {
            Console.WriteLine("===== История операций =====");
            foreach (var log in logs)
            {
                Console.WriteLine($"ID: {log.LogId}");
                Console.WriteLine($"Действие: {log.ActionType}");
                Console.WriteLine($"Результат: {log.ActionResult}");
                Console.WriteLine($"Время: {log.Timestamp}");
                Console.WriteLine("--------------------------");
            }
        }
    }

    private static async Task<User?> HandleChangePassword(AuthVal validator, ApiH apiHandler, User? activeUser)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Сначала войдите!");
            return null;
        }

        Console.Write("Старый пароль: ");
        string oldPwd = Console.ReadLine() ?? "";
        Console.Write("Новый пароль: ");
        string newPwd = Console.ReadLine() ?? "";
        
        if (!validator.ValPass(newPwd))
        {
            Console.WriteLine("Новый пароль не подходит!");
            return activeUser;
        }

        Console.WriteLine("Смена пароля...");
        var changePwdResult = await apiHandler.ChangePassword(oldPwd, newPwd);
        
        if (changePwdResult)
        {
            Console.WriteLine("✓ Пароль успешно изменен.");
            await apiHandler.Logout();
            Console.WriteLine("Пожалуйста, войдите снова с новым паролем.");
            return null;
        }
        else
        {
            Console.WriteLine("✗ Ошибка смены пароля.");
            return activeUser;
        }
    }

    private static async Task<User?> HandleDeleteAccount(ApiH apiHandler, UserRepo userRepo, User? activeUser)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Сначала войдите!");
            return null;
        }

        Console.Write("Вы уверены, что хотите удалить аккаунт? (да/нет): ");
        string confirm = Console.ReadLine()?.ToLower() ?? "";
        
        if (confirm != "да")
        {
            Console.WriteLine("Удаление отменено.");
            return activeUser;
        }

        Console.WriteLine("Удаление аккаунта...");
        var deleteResult = await apiHandler.DeleteAccount();
        
        if (deleteResult)
        {
            Console.WriteLine("✓ Аккаунт успешно удален.");
            userRepo.RmvUsr(activeUser.Uid);
            return null;
        }
        else
        {
            Console.WriteLine("✗ Ошибка удаления аккаунта.");
            return activeUser;
        }
    }

    private static async Task<User?> HandleLogout(ApiH apiHandler, User? activeUser)
    {
        if (activeUser == null)
        {
            Console.WriteLine("Вы не вошли в аккаунт.");
            return null;
        }

        Console.WriteLine("Выход из аккаунта...");
        await apiHandler.Logout();
        Console.WriteLine($"✓ Пользователь {activeUser.Username} вышел из аккаунта.");
        return null;
    }

    private static void ShowHelp()
    {
        Console.WriteLine(@"
===== Справка по Hill Cipher API =====

- API использует шифр Хилла с матрицей 2x2
- Поддерживает символы: A-Z, 0-9, пробел
- Ключ должен быть в формате: число,число,число,число
- Пример ключа: 6,24,13,16
- Если не указать ключ, используется ключ по умолчанию
- Если не указать текст при шифровании, используется 'Hello World'

Доступные команды:
1. Регистрация - создание нового аккаунта
2. Вход - вход в существующий аккаунт
3. Проверить пользователя - информация о текущем пользователе
4. Шифровать текст - зашифровать текст
5. Дешифровать текст - расшифровать текст
6. История операций - просмотр истории действий
7. Сменить пароль - изменение пароля
8. Удалить аккаунт - удаление аккаунта
9. Выход - выход из аккаунта
10. Справка - эта информация
11. Проверить соединение - тест подключения к серверу

ВАЖНО: Перед использованием убедитесь, что сервер запущен!
Сервер должен быть доступен по адресу: http://localhost:5014
");
    }
}

public class UserRepo
{
    private const string dbp = "Data Source=hillcipher_client.db";

    public UserRepo()
    {
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = @"
                    CREATE TABLE IF NOT EXISTS UsersLoc (
                        uid INTEGER PRIMARY KEY AUTOINCREMENT,
                        sUid INTEGER,
                        nm TEXT NOT NULL UNIQUE,
                        sett TEXT DEFAULT 'BOTH'
                    );";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.ExecuteNonQuery();
                    Console.WriteLine("✓ База данных клиента инициализирована");
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"✗ Ошибка инициализации БД пользователей: {e.Message}");
        }
    }

    public User InsUsr(string nm, int sUid = 0, string sett = "BOTH")
    {
        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = "INSERT INTO UsersLoc (sUid, nm, sett) VALUES (@su, @n, @st);";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@su", sUid);
                    cmd.Parameters.AddWithValue("@n", nm);
                    cmd.Parameters.AddWithValue("@st", sett);
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = "SELECT last_insert_rowid();";
                    long id = (long)cmd.ExecuteScalar();

                    return new User
                    {
                        Uid = (int)id,
                        ServerUid = sUid,
                        Username = nm,
                        Settings = sett
                    };
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка добавления пользователя: {ex.Message}");
            return null;
        }
    }

    public User FindByNm(string nm)
    {
        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = "SELECT uid, sUid, nm, sett FROM UsersLoc WHERE nm=@n;";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@n", nm);

                    using (var rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                        {
                            return new User
                            {
                                Uid = Convert.ToInt32(rdr["uid"]),
                                ServerUid = rdr["sUid"] == DBNull.Value ? 0 : Convert.ToInt32(rdr["sUid"]),
                                Username = rdr["nm"].ToString(),
                                Settings = rdr["sett"].ToString()
                            };
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка поиска пользователя: {ex.Message}");
        }
        return null;
    }
    
    public User RmvUsr(int uid)
    {
        try
        {
            var user = GetById(uid);
            if (user == null) return null;

            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = "DELETE FROM UsersLoc WHERE uid=@id;";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@id", uid);
                    cmd.ExecuteNonQuery();
                    return user;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка удаления пользователя: {ex.Message}");
            return null;
        }
    }
    
    private User GetById(int uid)
    {
        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = "SELECT uid, sUid, nm, sett FROM UsersLoc WHERE uid=@id;";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@id", uid);

                    using (var rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                        {
                            return new User
                            {
                                Uid = Convert.ToInt32(rdr["uid"]),
                                ServerUid = rdr["sUid"] == DBNull.Value ? 0 : Convert.ToInt32(rdr["sUid"]),
                                Username = rdr["nm"].ToString(),
                                Settings = rdr["sett"].ToString()
                            };
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка получения пользователя: {ex.Message}");
        }
        return null;
    }
}

public class ActLog
{
    private const string dbp = "Data Source=hillcipher_client.db";

    public ActLog()
    {
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = @"
                    CREATE TABLE IF NOT EXISTS Logs (
                        logId INTEGER PRIMARY KEY AUTOINCREMENT,
                        uOwner INTEGER NOT NULL,
                        type TEXT NOT NULL,
                        txt INTEGER NOT NULL,
                        result TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    );";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"✗ Ошибка инициализации БД логов: {e.Message}");
        }
    }

    public void Add(ActionRecord r)
    {
        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = "INSERT INTO Logs (uOwner, type, txt, result) VALUES (@u, @t, @tx, @res);";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@u", r.UserOwner);
                    cmd.Parameters.AddWithValue("@t", r.ActionType);
                    cmd.Parameters.AddWithValue("@tx", r.Text);
                    cmd.Parameters.AddWithValue("@res", r.ActionResult);
                    cmd.ExecuteNonQuery();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка добавления лога: {ex.Message}");
        }
    }

    public List<ActionRecord> GetActions(int u)
    {
        var lst = new List<ActionRecord>();

        try
        {
            using (var conn = new SqliteConnection(dbp))
            {
                conn.Open();
                string sql = "SELECT logId, uOwner, type, txt, result, timestamp FROM Logs WHERE uOwner=@u ORDER BY timestamp DESC;";
                
                using (var cmd = new SqliteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@u", u);

                    using (var rdr = cmd.ExecuteReader())
                    {
                        while (rdr.Read())
                        {
                            lst.Add(new ActionRecord
                            {
                                LogId = Convert.ToInt32(rdr["logId"]),
                                UserOwner = Convert.ToInt32(rdr["uOwner"]),
                                ActionType = rdr["type"].ToString(),
                                Text = Convert.ToInt32(rdr["txt"]),
                                ActionResult = rdr["result"].ToString(),
                                Timestamp = rdr["timestamp"] != DBNull.Value ? Convert.ToDateTime(rdr["timestamp"]) : DateTime.MinValue
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка получения логов: {ex.Message}");
        }

        return lst;
    }
}

public class ApiH
{
    private HttpClient http;
    private string baseUrl;

    public ApiH(string url = "http://localhost:5014")
    {
        baseUrl = url;
        Console.WriteLine($"✓ API клиент инициализирован для {baseUrl}");
        
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer(),
            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
        };
        
        http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        http.BaseAddress = new Uri(baseUrl);
        http.DefaultRequestHeaders.Add("User-Agent", "HillCipherClient");
        
        Console.WriteLine("✓ HttpClient настроен");
    }

    public async Task<SignupResponse> Signup(string login, string password)
    {
        try
        {
            Console.WriteLine($"Отправка POST запроса на {baseUrl}/signup");
            var request = new SignupRequest { Login = login, Password = password };
            var response = await http.PostAsJsonAsync("/signup", request);
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<SignupResponse>();
                Console.WriteLine($"✓ Регистрация успешна: {result?.message}");
                return result;
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"✗ Ошибка регистрации: {response.StatusCode}");
                Console.WriteLine($"Тело ошибки: {error}");
                return new SignupResponse { success = false, message = error };
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"✗ Сетевая ошибка при регистрации: {ex.Message}");
            Console.WriteLine($"Проверьте адрес сервера: {baseUrl}");
            return new SignupResponse { success = false, message = ex.Message };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Неожиданная ошибка при регистрации: {ex.Message}");
            return new SignupResponse { success = false, message = ex.Message };
        }
    }

    public async Task<LoginResponse> Login(string login, string password)
    {
        try
        {
            Console.WriteLine($"Отправка POST запроса на {baseUrl}/login");
            var request = new LoginRequest { Login = login, Password = password };
            var response = await http.PostAsJsonAsync("/login", request);
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
                Console.WriteLine($"✓ Вход успешен: {result?.message}");
                return result;
            }
            else
            {
                Console.WriteLine($"✗ Ошибка входа: {response.StatusCode}");
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Тело ответа: {content}");
                return new LoginResponse { success = false, message = content };
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"✗ Сетевая ошибка при входе: {ex.Message}");
            return new LoginResponse { success = false, message = ex.Message };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Неожиданная ошибка при входе: {ex.Message}");
            return new LoginResponse { success = false, message = ex.Message };
        }
    }

    public async Task<UserResponse> CheckUser()
    {
        try
        {
            Console.WriteLine($"Отправка GET запроса на {baseUrl}/check_user");
            var response = await http.GetAsync("/check_user");
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<UserResponse>();
                Console.WriteLine("✓ Получена информация о пользователе");
                return result;
            }
            
            Console.WriteLine($"✗ Ошибка проверки пользователя: {response.StatusCode}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка при проверке пользователя: {ex.Message}");
            return null;
        }
    }

    public async Task<HillCipherResult> Encrypt(string text, string key = null)
    {
        try
        {
            string url = $"/encrypt?text={Uri.EscapeDataString(text)}";
            if (!string.IsNullOrEmpty(key))
            {
                url += $"&key={Uri.EscapeDataString(key)}";
            }
            
            Console.WriteLine($"Отправка GET запроса на {baseUrl}{url}");
            var response = await http.GetAsync(url);
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<HillCipherResult>();
                Console.WriteLine("✓ Шифрование успешно");
                return result;
            }
            
            Console.WriteLine($"✗ Ошибка шифрования: {response.StatusCode}");
            var error = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Тело ошибки: {error}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка при шифровании: {ex.Message}");
            return null;
        }
    }

    public async Task<HillCipherResult> Decrypt(string ciphertext, string key = null)
    {
        try
        {
            string url = $"/decrypt?ciphertext={Uri.EscapeDataString(ciphertext)}";
            if (!string.IsNullOrEmpty(key))
            {
                url += $"&key={Uri.EscapeDataString(key)}";
            }
            
            Console.WriteLine($"Отправка GET запроса на {baseUrl}{url}");
            var response = await http.GetAsync(url);
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<HillCipherResult>();
                Console.WriteLine("✓ Дешифрование успешно");
                return result;
            }
            
            Console.WriteLine($"✗ Ошибка дешифрования: {response.StatusCode}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка при дешифровании: {ex.Message}");
            return null;
        }
    }

    public async Task<bool> ChangePassword(string oldPassword, string newPassword)
    {
        try
        {
            var request = new ChangePasswordRequest
            {
                OldPassword = oldPassword,
                NewPassword = newPassword
            };

            Console.WriteLine($"Отправка POST запроса на {baseUrl}/change_password");
            var response = await http.PostAsJsonAsync("/change_password", request);
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("✓ Пароль успешно изменен");
                return true;
            }
            else
            {
                Console.WriteLine($"✗ Ошибка смены пароля: {response.StatusCode}");
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Тело ошибки: {error}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка при смене пароля: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> DeleteAccount()
    {
        try
        {
            Console.WriteLine($"Отправка DELETE запроса на {baseUrl}/account");
            var response = await http.DeleteAsync("/account");
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("✓ Аккаунт успешно удален");
                return true;
            }
            else
            {
                Console.WriteLine($"✗ Ошибка удаления аккаунта: {response.StatusCode}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка при удалении аккаунта: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> Logout()
    {
        try
        {
            Console.WriteLine($"Отправка POST запроса на {baseUrl}/logout");
            var response = await http.PostAsync("/logout", null);
            
            Console.WriteLine($"Статус ответа: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("✓ Выход успешен");
                return true;
            }
            else
            {
                Console.WriteLine($"✗ Ошибка выхода: {response.StatusCode}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Ошибка при выходе: {ex.Message}");
            return false;
        }
    }
}

public class User
{
    public int Uid { get; set; }
    public int ServerUid { get; set; }
    public string Username { get; set; }
    public string Settings { get; set; }
}

public class ActionRecord
{
    public int LogId { get; set; }
    public int UserOwner { get; set; }
    public string ActionType { get; set; }
    public int Text { get; set; }
    public string ActionResult { get; set; }
    public DateTime Timestamp { get; set; }
}

public class LoginRequest
{
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginResponse
{
    public bool success { get; set; }
    public string message { get; set; } = string.Empty;
    public UserDto user { get; set; }
}

public class SignupRequest
{
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class SignupResponse
{
    public bool success { get; set; }
    public string message { get; set; } = string.Empty;
    public UserDto user { get; set; }
}

public class ChangePasswordRequest
{
    public string OldPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class UserResponse
{
    public int Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class UserDto
{
    public int Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class HillCipherResult
{
    public string Result { get; set; } = string.Empty;
    public string Key { get; set; } = string.Empty;
}

public class AuthVal
{
    public bool ValLogin(string l)
    {
        if (string.IsNullOrWhiteSpace(l))
            return false;

        if (l.Length < 4 || l.Length > 20)
            return false;

        return Regex.IsMatch(l, @"^[a-zA-Z0-9_]+$");
    }

    public bool ValPass(string p)
    {
        if (string.IsNullOrWhiteSpace(p))
            return false;

        if (p.Length < 8)
            return false;

        int digits = p.Count(char.IsDigit);
        bool hasL = p.Any(char.IsLetter);

        return hasL && digits >= 2;
    }

    public bool ValKey(string k)
    {
        if (string.IsNullOrWhiteSpace(k))
            return true;

        if (!Regex.IsMatch(k, @"^\d+,\d+,\d+,\d+$"))
            return false;
            
        var parts = k.Split(',');
        foreach (var part in parts)
        {
            if (!int.TryParse(part, out _))
                return false;
        }
        
        return true;
    }
}