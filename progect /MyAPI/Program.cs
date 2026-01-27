using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();


string DB_PATH = "/home/vboxuser/Documents/progect /MyAPI/DB_users.db";

DBManager dbManager = new DBManager();
HillCipherService cipherService = new HillCipherService();


if (!dbManager.ConnectToDB(DB_PATH))
{
    Console.WriteLine("Warning: Failed to connect to database.");
}

app.MapGet("/", () => "Hill Cipher API - Encrypt/Decrypt text using Hill Cipher.");

app.MapGet("/encrypt", [Authorize] ([FromQuery] string? text, [FromQuery] string? key) => 
{
    if (string.IsNullOrEmpty(text))
        text = "Hello World";
    
    try
    {
        var result = cipherService.Encrypt(text, key);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Encryption failed: {ex.Message}");
    }
});

app.MapGet("/decrypt", [Authorize] ([FromQuery] string ciphertext, [FromQuery] string? key) => 
{
    try
    {
        var result = cipherService.Decrypt(ciphertext, key);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Decryption failed: {ex.Message}");
    }
});


app.MapPost("/login", async ([FromBody] LoginRequest request, HttpContext context) => 
{
    if (string.IsNullOrEmpty(request.Login) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { error = "Login and password are required" });
    }
    
    var user = dbManager.AuthenticateUser(request.Login, request.Password);
    if (user != null)
    {
        var claims = new List<Claim> 
        { 
            new Claim(ClaimTypes.Name, user.Login),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim("UserId", user.Id.ToString())
        };
        
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(2)
        };
        
        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);
        
        return Results.Ok(new 
        { 
            success = true, 
            message = "Login successful", 
            user = new 
            {
                Id = user.Id,
                Login = user.Login,
                CreatedAt = user.CreatedAt
            }
        });
    }
    
    return Results.Unauthorized();
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { message = "Logged out" });
});

app.MapGet("/check_user", [Authorize] (HttpContext context) =>
{
    var user = GetCurrentUser(context, dbManager);
    if (user == null)
        return Results.BadRequest(new { error = "User is unknown" });
    
    return Results.Ok(new 
    { 
        Id = user.Id,
        Login = user.Login,
        CreatedAt = user.CreatedAt 
    });
});

app.MapPost("/signup", ([FromBody] SignupRequest request) => 
{
    if (string.IsNullOrEmpty(request.Login) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { error = "Login and password are required" });
    }
    
    var user = dbManager.RegisterUser(request.Login, request.Password);
    if (user != null)
        return Results.Ok(new 
        { 
            success = true,
            message = $"User {request.Login} registered successfully!", 
            user = new 
            {
                Id = user.Id,
                Login = user.Login,
                CreatedAt = user.CreatedAt
            }
        });
    else
        return Results.BadRequest(new { error = $"Failed to register user {request.Login}" });
});

app.MapPost("/change_password", [Authorize] ([FromBody] ChangePasswordRequest request, HttpContext context) =>
{
    var user = GetCurrentUser(context, dbManager);
    if (user == null)
        return Results.Unauthorized();
    
    if (dbManager.ChangePassword(user.Id, request.OldPassword, request.NewPassword))
        return Results.Ok(new { message = "Password changed successfully" });
    
    return Results.BadRequest(new { error = "Failed to change password" });
});

app.MapDelete("/account", [Authorize] (HttpContext context) =>
{
    var user = GetCurrentUser(context, dbManager);
    if (user == null)
        return Results.Unauthorized();

    if (dbManager.DeleteUser(user.Id))
        return Results.Ok(new { message = "Account deleted" });

    return Results.BadRequest(new { error = "Failed to delete account" });
});

User? GetCurrentUser(HttpContext context, DBManager dbManager)
{
    var userIdClaim = context.User.FindFirst("UserId");
    if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int userId))
        return null;
    
    return dbManager.GetUserById(userId);
}

app.Run();

public class LoginRequest
{
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class SignupRequest
{
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class ChangePasswordRequest
{
    public string OldPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class User
{
    public int Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class HillCipherResult
{
    public HillCipherResult(string result, string? key = null)
    {
        Result = result;
        Key = key;
    }
    
    public string Result { get; set; }
    public string? Key { get; set; }
}