﻿using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;



class Program
{
    static void Main() //Вибір защифрувати чи розшифрувати
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Виберіть режим роботи програми (Впишіть 1 для зашифрування, 2 для розшифрування): ");
        string choice = Console.ReadLine();

        if (choice == "1")
        {
            EncryptData();
        }
        else if (choice == "2")
        {
            DecryptData();
        }
        else
        {
            Console.WriteLine("Невірний вибір. Завершення програми.");
        }
    }

    static void EncryptData()  //Зашифрування
    {
        //Визаначення паролю для шифрування 
        string password = GetSecurePassword(); // Безпечний ввід пароля
        byte[] salt = new byte[16];
        byte[] iv = new byte[16]; // 128 біт для AES

        // Генерація криптографічно стійких значень для salt і IV
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
            rng.GetBytes(iv);
        }

        // Встановлення параметрів для PBKDF2 (для створення надійного криптографічного ключа з паролю)
        int iterations = 100000;
        int keyLength = 32;
        byte[] key;

        // Отримання ключа шифрування за допомогою PBKDF2 та пароля
        using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
        {
            key = kdf.GetBytes(keyLength);
        }
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Введіть ваші дані");

        //Місце для вводу даних для шифрування у байтовому вигляді
        byte[] data = Encoding.UTF8.GetBytes(Console.ReadLine());
        data = AddPadding(data); // Доповнення даних для AES (PKCS7)

        byte[] encryptedData;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key; // Встановлення ключа шифрування
            aesAlg.IV = iv;  // Встановлення IV для CBC
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.None;

            using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
            {
                encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length); // Шифрування даних
            }
        }

        // Генерація MAC для автентифікації шифрованих даних
        byte[] mac;
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            mac = hmac.ComputeHash(encryptedData); // Розрахунок HMAC
        }
        Console.WriteLine("Введіть назву файлу (не вказувати формат)");

        // Збереження всіх компонентів у файл
        Console.InputEncoding = Encoding.UTF8;
        string fileName;
        while (true)
        {
            Console.InputEncoding = Encoding.UTF8;
            fileName = Console.ReadLine()?.Trim();

            // Перевірка на порожній або некоректний ввід
            if (string.IsNullOrEmpty(fileName))
            {
                Console.WriteLine("Назва файлу не може бути порожньою. Будь ласка, введіть коректну назву.");
            }
            else if (fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                Console.WriteLine("Назва файлу містить недопустимі символи. Спробуйте ще раз.");
            }
            else
            {
                break; // Умова виконана, вихід із циклу
            }
        }
        using (var fileStream = new FileStream(fileName + ".bin", FileMode.Create))
        {
            fileStream.Write(salt, 0, salt.Length);  // Запис salt
            fileStream.Write(iv, 0, iv.Length); // Запис IV
            fileStream.Write(mac, 0, mac.Length); // Запис MAC
            fileStream.Write(encryptedData, 0, encryptedData.Length); // Запис зашифрованих даних
        }

        Console.WriteLine("Дані успішно зашифровані та збережені.");
    }

    static void DecryptData()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        Console.WriteLine("Введіть назву файлу (не вказувати формат)");

        string fileName;
        while (true)
        {
            Console.InputEncoding = Encoding.UTF8;
            fileName = Console.ReadLine()?.Trim();

            // Перевірка на порожній або некоректний ввід
            if (string.IsNullOrEmpty(fileName))
            {
                Console.WriteLine("Назва файлу не може бути порожньою. Будь ласка, введіть коректну назву.");
            }
            else if (fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                Console.WriteLine("Назва файлу містить недопустимі символи. Спробуйте ще раз.");
            }
            else
            {
                string fullPath = fileName + ".bin";
                if (!File.Exists(fullPath))
                {
                    Console.WriteLine($"Файл {fullPath} не знайдено. Будь ласка, введіть існуючий файл.");
                }
                else
                {
                    break; // Умова виконана, вихід із циклу
                }
            }
        }
        // Читання зашифрованого файлу
        byte[] fileContent = File.ReadAllBytes(fileName + ".bin");


        // Розділення вмісту файлу на salt, iv, mac та зашифровані дані
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        byte[] mac = new byte[32];
        byte[] encryptedData = new byte[fileContent.Length - (salt.Length + iv.Length + mac.Length)];

        Array.Copy(fileContent, 0, salt, 0, salt.Length);// Вилучення salt
        Array.Copy(fileContent, salt.Length, iv, 0, iv.Length); // Вилучення IV
        Array.Copy(fileContent, salt.Length + iv.Length, mac, 0, mac.Length); // Вилучення MAC
        Array.Copy(fileContent, salt.Length + iv.Length + mac.Length, encryptedData, 0, encryptedData.Length); // Вилучення зашифрованих даних

        // Визначення пароля для розшифрування
        string password = GetSecurePassword(); // Пароль, який має співпадати з паролем зашифрування
        int iterations = 100000;
        int keyLength = 32;
        byte[] key;

        // Відтворення ключа з пароля та salt за допомогою PBKDF2
        using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
        {
            key = kdf.GetBytes(keyLength);
        }

        // Перевірка MAC на відповідність
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            byte[] computedMac = hmac.ComputeHash(encryptedData);
            if (!CompareBytes(mac, computedMac))
            {
                throw new CryptographicException("Автентифікація не пройдена! MAC не співпадає.");
            }
        }

        // Розшифрування даних AES у режимі CBC
        byte[] decryptedPaddedData;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;// Встановлення ключа
            aesAlg.IV = iv;// Встановлення IV
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.None;

            using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            {
                decryptedPaddedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            }
        }

        // Видалення доповнення (PKCS7) після розшифрування
        byte[] decryptedData = RemovePadding(decryptedPaddedData);
        string decryptedText = Encoding.UTF8.GetString(decryptedData); // Перетворення байтів у текст
        Console.WriteLine("Розшифровані дані: " + decryptedText);
    }

    //Метод для введення безпечного пароля
    static string GetSecurePassword()
    {
        Console.InputEncoding = Encoding.UTF8;

        while (true) // Додаємо цикл для повторного введення паролю
        {
            Console.WriteLine("Введіть пароль (не менше 8 символів):");
            StringBuilder password = new StringBuilder();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Length--;
                    Console.Write("\b \b");
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
            } while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();

            // Перевірка на порожній пароль або довжину менше 8 символів
            if (password.Length == 0)
            {
                Console.WriteLine("Пароль не може бути порожнім.");
            }
            else if (password.Length < 8)
            {
                Console.WriteLine("Пароль занадто короткий. Спробуйте ще раз.");
            }
            else
            {
                return password.ToString(); // Пароль валідний, повертаємо результат
            }
        }
    }

    // Метод для доповнення даних (PKCS7)
    static byte[] AddPadding(byte[] data)
    {
        int blockSize = 16;
        int paddingSize = blockSize - (data.Length % blockSize);
        byte[] paddedData = new byte[data.Length + paddingSize];
        Array.Copy(data, paddedData, data.Length);
        for (int i = data.Length; i < paddedData.Length; i++)
        {
            paddedData[i] = (byte)paddingSize;
        }
        return paddedData;
    }

    static byte[] RemovePadding(byte[] data)
    {
        int paddingSize = data[data.Length - 1];
        byte[] result = new byte[data.Length - paddingSize];
        Array.Copy(data, result, result.Length);
        return result;
    }

    static bool CompareBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
