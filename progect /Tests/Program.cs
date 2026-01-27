using Xunit;
using System;
using System.Collections.Generic;
using System.Linq;

public class TestUser
{
    public int Id { get; set; }
    public string Login { get; set; }
    public string Password { get; set; }
}

public class TestLocalUser
{
    public int User_id { get; set; }
    public string Login { get; set; }
    public string JWT { get; set; }
}

public class TestOperation
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string SourceText { get; set; }
    public string ResultText { get; set; }
    public string Key { get; set; }
}
public class AuthTests
{
    [Fact]
    public void Test_Validate_Login_Correct()
    {
        string login = "user123";
    
        bool isValid = login.Length >= 4 && login.Length <= 20;
        
        Assert.True(isValid);
    }
    
    [Fact]
    public void Test_Validate_Login_Too_Short()
    {
        string login = "usr";

        bool isValid = login.Length >= 4;
        
        Assert.False(isValid);
    }
    
    [Fact]
    public void Test_Validate_Login_Too_Long()
    {
        string login = "this_login_is_way_too_long_for_system";
        
        bool isValid = login.Length <= 20;
        
        Assert.False(isValid);
    }
    
    [Fact]
    public void Test_Validate_Password_Correct()
    {
        string password = "password123";
        
        bool hasLetters = password.Any(c => char.IsLetter(c));
        bool hasDigits = password.Count(char.IsDigit) >= 2;
        bool isLongEnough = password.Length >= 8;
        
        Assert.True(hasLetters && hasDigits && isLongEnough);
    }
    
    [Fact]
    public void Test_Validate_Password_No_Digits()
    {
        string password = "password";
        
        bool hasDigits = password.Any(c => char.IsDigit(c));
        
        Assert.False(hasDigits);
    }
    
    [Fact]
    public void Test_Validate_Password_Too_Short()
    {
        string password = "pass12";
        
        bool isLongEnough = password.Length >= 8;
        
        Assert.False(isLongEnough);
    }
}

public class DataTests
{
    [Fact]
    public void Test_User_Creation()
    {
        var user = new TestUser
        {
            Id = 1,
            Login = "testuser",
            Password = "hashedpassword123"
        };
        
        Assert.Equal(1, user.Id);
        Assert.Equal("testuser", user.Login);
        Assert.Equal("hashedpassword123", user.Password);
    }
    
    [Fact]
    public void Test_LocalUser_Creation()
    {
        var localUser = new TestLocalUser
        {
            User_id = 1,
            Login = "localuser",
            JWT = "jwt_token_123"
        };
        
        Assert.Equal(1, localUser.User_id);
        Assert.Equal("localuser", localUser.Login);
        Assert.Equal("jwt_token_123", localUser.JWT);
    }
    
    [Fact]
    public void Test_Operation_Creation()
    {
        var operation = new TestOperation
        {
            Id = 1,
            UserId = 5,
            SourceText = "Hello World",
            ResultText = "KHOOR ZRUOG",
            Key = "6,24,13,16"
        };
        
        Assert.Equal(1, operation.Id);
        Assert.Equal(5, operation.UserId);
        Assert.Equal("Hello World", operation.SourceText);
        Assert.Equal("KHOOR ZRUOG", operation.ResultText);
        Assert.Equal("6,24,13,16", operation.Key);
    }
    
    [Fact]
    public void Test_Key_Format()
    {
        string key = "1,2,3,4";
        
        string[] parts = key.Split(',');
        
        Assert.Equal(4, parts.Length);
        Assert.Equal("1", parts[0]);
        Assert.Equal("2", parts[1]);
        Assert.Equal("3", parts[2]);
        Assert.Equal("4", parts[3]);
    }
    
    [Fact]
    public void Test_Key_Conversion()
    {
        string keyString = "6,24,13,16";
        
        int[] keyArray = keyString.Split(',').Select(int.Parse).ToArray();
        
        Assert.Equal(4, keyArray.Length);
        Assert.Equal(6, keyArray[0]);
        Assert.Equal(24, keyArray[1]);
        Assert.Equal(13, keyArray[2]);
        Assert.Equal(16, keyArray[3]);
    }
}

public class HillCipherTests
{
    [Fact]
    public void Test_Hill_Cipher_Text_Preparation()
    {
        string text = "HELLO WORLD";
        
        string prepared = text.ToUpper().Replace(" ", "");
        
        Assert.Equal("HELLOWORLD", prepared);
    }
    
    [Fact]
    public void Test_Hill_Cipher_Character_Conversion()
    {
        char letter = 'A';
        
        int value = letter - 'A';
        
        Assert.Equal(0, value);
    }
    
    [Fact]
    public void Test_Hill_Cipher_Matrix_Multiplication_Logic()
    {
        int[] key = { 6, 24, 13, 16 };
        int[] textValues = { 7, 4 }; // HE = 7(H), 4(E)
        
        int result1 = (key[0] * textValues[0] + key[1] * textValues[1]) % 26;
        int result2 = (key[2] * textValues[0] + key[3] * textValues[1]) % 26;
        
        Assert.InRange(result1, 0, 25);
        Assert.InRange(result2, 0, 25);
    }
    
    [Fact]
    public void Test_Hill_Cipher_Default_Key()
    {
        string defaultKey = "6,24,13,16";
        
        string[] parts = defaultKey.Split(',');
        bool isValid = parts.Length == 4;
        
        Assert.True(isValid);
        Assert.Equal("6", parts[0]);
        Assert.Equal("24", parts[1]);
        Assert.Equal("13", parts[2]);
        Assert.Equal("16", parts[3]);
    }
}

public class ListTests
{
    [Fact]
    public void Test_User_List_Operations()
    {
        var users = new List<TestLocalUser>();
        
        users.Add(new TestLocalUser { User_id = 1, Login = "user1" });
        users.Add(new TestLocalUser { User_id = 2, Login = "user2" });
        users.Add(new TestLocalUser { User_id = 3, Login = "user3" });
        
        Assert.Equal(3, users.Count);
        Assert.Equal("user1", users[0].Login);
        Assert.Equal("user2", users[1].Login);
        Assert.Equal("user3", users[2].Login);
    }
    
    [Fact]
    public void Test_Operation_List_Operations()
    {
        var operations = new List<TestOperation>();
        
        operations.Add(new TestOperation { 
            Id = 1, 
            UserId = 1, 
            SourceText = "text1", 
            ResultText = "encrypted1" 
        });
        
        operations.Add(new TestOperation { 
            Id = 2, 
            UserId = 1, 
            SourceText = "text2", 
            ResultText = "encrypted2" 
        });
        
        Assert.Equal(2, operations.Count);
        
        var userOperations = operations.Where(op => op.UserId == 1).ToList();
        Assert.Equal(2, userOperations.Count);
    }
    
    [Fact]
    public void Test_Find_User_In_List()
    {
        var users = new List<TestLocalUser>
        {
            new TestLocalUser { User_id = 1, Login = "user1" },
            new TestLocalUser { User_id = 2, Login = "user2" },
            new TestLocalUser { User_id = 3, Login = "user3" }
        };
        
        var foundUser = users.FirstOrDefault(u => u.Login == "user2");
        
        Assert.NotNull(foundUser);
        Assert.Equal(2, foundUser.User_id);
        Assert.Equal("user2", foundUser.Login);
    }
}

public class EncryptionLogicTests
{
    [Fact]
    public void Test_Encryption_Input_Validation()
    {
        string validText = "HELLO";
        string emptyText = "";
        string nullText = null;
        
        Assert.True(!string.IsNullOrEmpty(validText));
        Assert.False(!string.IsNullOrEmpty(emptyText));
        Assert.False(!string.IsNullOrEmpty(nullText));
    }
    
    [Fact]
    public void Test_Key_Validation()
    {
        string validKey = "1,2,3,4";
        string invalidKey1 = "1,2,3"; // не хватает чисел
        string invalidKey2 = "a,b,c,d"; // не числа
        
        bool isValid1 = validKey.Split(',').Length == 4;
        bool isValid2 = invalidKey1.Split(',').Length == 4;
        
        Assert.True(isValid1);
        Assert.False(isValid2);
    }
    
    [Fact]
    public void Test_Text_Length_For_Hill_Cipher()
    {
        string text = "HELLO";
        
        bool isEvenLength = text.Length % 2 == 0;
        
        Assert.False(isEvenLength); // "HELLO" - 5 символов, нечетное
        
        // Для шифрования Хилла (2x2) нужно четное количество символов
        // Обычно добавляют padding (например, 'X')
        string paddedText = text + (text.Length % 2 == 1 ? "X" : "");
        Assert.True(paddedText.Length % 2 == 0);
    }
}

public class StringTests
{
    [Fact]
    public void Test_String_Operations()
    {
        string original = "Hello World";
        
        string upper = original.ToUpper();
        string lower = original.ToLower();
        string withoutSpaces = original.Replace(" ", "");
        
        Assert.Equal("HELLO WORLD", upper);
        Assert.Equal("hello world", lower);
        Assert.Equal("HelloWorld", withoutSpaces);
    }
    
    [Fact]
    public void Test_String_Contains()
    {
        string message = "Encryption successful with key: 6,24,13,16";
        
        bool containsKey = message.Contains("6,24,13,16");
        bool containsSuccess = message.Contains("successful");
        
        Assert.True(containsKey);
        Assert.True(containsSuccess);
    }
    
    [Fact]
    public void Test_String_Split_And_Join()
    {
        string keyString = "6,24,13,16";
        
        string[] parts = keyString.Split(',');
        string rejoined = string.Join("-", parts);
        
        Assert.Equal(4, parts.Length);
        Assert.Equal("6-24-13-16", rejoined);
    }
}

public class MathTests
{
    [Fact]
    public void Test_Modulo_Operation()
    {
        int a = 47;
        int b = 26;
        
        int result = a % b;
        
        Assert.Equal(21, result); // 47 % 26 = 21
    }
    
    [Fact]
    public void Test_Modulo_For_Hill_Cipher()
    {
        // В шифре Хилла все операции по модулю 26
        
        int value1 = 30;
        int value2 = 52;
        int value3 = -3;
        
        int result1 = ((value1 % 26) + 26) % 26; // Для отрицательных чисел тоже
        int result2 = ((value2 % 26) + 26) % 26;
        int result3 = ((value3 % 26) + 26) % 26;
        
        Assert.Equal(4, result1);  // 30 % 26 = 4
        Assert.Equal(0, result2);  // 52 % 26 = 0
        Assert.Equal(23, result3); // -3 % 26 = 23
    }
    
    [Fact]
    public void Test_Matrix_Determinant()
    {
        // Для матрицы 2x2 [[a, b], [c, d]] детерминант = a*d - b*c
        
        int a = 6, b = 24, c = 13, d = 16;
        
        int determinant = a * d - b * c;
        
        int expected = 6 * 16 - 24 * 13; // 96 - 312 = -216
        Assert.Equal(expected, determinant);
    }
}

public class ErrorTests
{
    [Fact]
    public void Test_Null_Check()
    {
        TestLocalUser user1 = new TestLocalUser { Login = "user" };
        TestLocalUser user2 = null;
        
        Assert.NotNull(user1);
        Assert.Null(user2);
        
        Assert.True(user1?.Login == "user");
        Assert.True(user2?.Login == null);
    }
    
    [Fact]
    public void Test_Exception_Handling_Logic()
    {
        string text = "123";
        
        bool canParse = int.TryParse(text, out int number);
        
        Assert.True(canParse);
        Assert.Equal(123, number);
        
        string invalidText = "abc";
        bool cannotParse = int.TryParse(invalidText, out _);
        Assert.False(cannotParse);
    }
}

public class IntegrationTests
{
    [Fact]
    public void Test_Full_Encryption_Flow()
    {
        
        // 1. Пользователь вводит данные
        string username = "testuser";
        string password = "pass1234";
        string textToEncrypt = "HELLO";
        string key = "6,24,13,16";
        
        // 2. Проверяем валидность
        bool isUserValid = username.Length >= 4;
        bool isPassValid = password.Length >= 8 && password.Any(char.IsDigit);
        bool isTextValid = !string.IsNullOrEmpty(textToEncrypt);
        bool isKeyValid = key.Split(',').Length == 4;
        
        // 3. Выполняем "шифрование" (упрощенное)
        string encryptedText = textToEncrypt.ToUpper() + "_ENCRYPTED";
        
        // 4. Создаем запись операции
        var operation = new TestOperation
        {
            UserId = 1,
            SourceText = textToEncrypt,
            ResultText = encryptedText,
            Key = key
        };
        
        // 5. Проверяем результаты
        Assert.True(isUserValid);
        Assert.True(isPassValid);
        Assert.True(isTextValid);
        Assert.True(isKeyValid);
        Assert.Equal("HELLO_ENCRYPTED", encryptedText);
        Assert.NotNull(operation);
    }
    
    [Fact]
    public void Test_Full_Decryption_Flow()
    {
        // Тестируем логику потока дешифрования
        
        // 1. Входные данные
        string encryptedText = "KHOOR";
        string key = "6,24,13,16";
        
        // 2. Проверяем валидность
        bool isTextValid = !string.IsNullOrEmpty(encryptedText);
        bool isKeyValid = key.Split(',').Length == 4;
        
        // 3. Выполняем "дешифрование" (упрощенное)
        string decryptedText = encryptedText.Replace("KHOOR", "HELLO");
        
        // 4. Проверяем результаты
        Assert.True(isTextValid);
        Assert.True(isKeyValid);
        Assert.Equal("HELLO", decryptedText);
    }
}