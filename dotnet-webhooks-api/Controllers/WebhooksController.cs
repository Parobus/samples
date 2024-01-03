using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Text.Json;

namespace WebhookDotNetTest.Controllers;


public class Payload
{
    public string? AdditionalInformation { get; set; }
    public int? Amount { get; set; }
    public int? AmountMax { get; set; }
    public Case? Case { get; set; }
    public List<string>? ExclusionReasons { get; set; }
    public ResultsIndex? Index { get; set; }
    public Lender? Lender { get; set; }
    public string? ScreenshotPdfUrl { get; set; }
    public string? Status { get; set; }
}

public class Case
{
    public string? Status { get; set; }
    public string? Uuid { get; set; }
}

public class ResultsIndex
{
    public int? Index { get; set; }
    public int? Total { get; set; }
}

public class PrimaryLender
{
    public bool? Btl { get; set; }
    public string? Name { get; set; }
    public object? Reference { get; set; }
    public bool? Resi { get; set; }
    public string? Type { get; set; }
}


public class Lender
{
    public bool Btl { get; set; }
    public string Name { get; set; }
    public List<Notice> Notices { get; set; }
    public PrimaryLender? PrimaryLender { get; set; }
    public object? Reference { get; set; }
    public bool Resi { get; set; }
    public string Type { get; set; }
}

public class Notice
{
    public int? AmountAtTimeOfReport { get; set; }
    public int? AverageAmountAtTimeOfReport { get; set; }
    public int? Occurences { get; set; }
}

public class WebhookBodyModel
{
    public Payload Payload { get; set; }
    public string Topic { get; set; }

    public Dictionary<string, object> PrimaryLenderToDictionary(PrimaryLender data)
    {
        if (data == null)
        {
            return null;
        }
        var jsonData = new Dictionary<string, object>
        {
            {"name", data.Name},
            {"type", data.Type},
            {"reference", data.Reference},
            {"resi", data.Resi},
            {"btl", data.Btl}
        };

        return jsonData;
    }

    public Dictionary<string, object> toDictionary(WebhookBodyModel data)
    {
        var jsonData = new Dictionary<string, object>
        {
            {
                "payload", new Dictionary<string, object>
                {
                    {"index", new Dictionary<string, object> {{"index", data.Payload.Index.Index }, {"total", data.Payload.Index.Total}}},
                    {"status", data.Payload.Status},
                    {
                        "case", new Dictionary<string, object>
                        {
                            {"status", data.Payload.Case.Status},
                            {"uuid", data.Payload.Case.Uuid}
                        }
                    },
                    {
                        "lender", new Dictionary<string, object>
                        {
                            {"name", data.Payload.Lender.Name},
                            {"type", data.Payload.Lender.Type},
                            {"reference", data.Payload.Lender.Reference},
                            {"resi", data.Payload.Lender.Resi},
                            {"btl", data.Payload.Lender.Btl},
                            {"notices", new List<object>(data.Payload.Lender.Notices.Select(n => new Dictionary<string, object>
                            {
                                {"amountAtTimeOfReport", n.AmountAtTimeOfReport},
                                {"averageAmountAtTimeOfReport", n.AverageAmountAtTimeOfReport},
                                {"occurences", n.Occurences}
                            }).ToList())},
                            { "primaryLender", PrimaryLenderToDictionary(data.Payload.Lender.PrimaryLender) }
                        }
                    },
                    {"amount", data.Payload.Amount},
                    {"additionalInformation", data.Payload.AdditionalInformation},
                    {"amountMax", data.Payload.AmountMax},
                    {"exclusionReasons", new List<object>(data.Payload.ExclusionReasons.Select(n => n).ToList())},
                    {"screenshotPdfUrl", data.Payload.ScreenshotPdfUrl}
                }
            },
            {"topic", data.Topic}
        };

        return jsonData;
    }
}


public enum Algorithm
{
    sha224,
    sha256,
    sha384,
    sha512
}
public struct Signature
{
    public Signature(DateTime timestamp, long timestampNanoSeconds, byte[] hash, Algorithm algorithm) : this()
    {
        Timestamp = timestamp;
        TimestampNanoSeconds = timestampNanoSeconds;
        Hash = hash;
        Algorithm = algorithm;
    }
    public DateTime Timestamp { get; private set; }
    public long TimestampNanoSeconds { get; private set; }
    public byte[] Hash { get; private set; }
    public Algorithm Algorithm { get; private set; }
}
public class SignatureParser
{
    public Signature Parse(string headerValue)
    {
        var parts = headerValue.Split(',');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid signature header");
        }
        if (!Int64.TryParse(parts[0].Split("=")[1], out var timestamp))
        {
            throw new ArgumentException("Invalid timestamp in signature header");
        }
        var epochNow = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var hashWithVersion = parts[1];
        Algorithm algorithm;
        Enum.TryParse<Algorithm>(parts[2].Split("=")[1], out algorithm);
        string hashString = string.Join("=", hashWithVersion.Split("=").Skip(1));
        var hash = Convert.FromBase64String(hashString);
        return new Signature(epochNow, timestamp, hash, algorithm);
    }
}
public class SignatureVerifier
{
    private static long NanosecondsToVerify = (long)1E+10;
    public bool Verify(Signature signature, string secretString, string payload)
    {
        var timestampAndPayload = signature.TimestampNanoSeconds + "." + payload;
        var epochNow = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var epochLast = epochNow.AddTicks(NanosecondsToVerify / 100);
        if (epochLast < signature.Timestamp)
        {
            return false;
        }
        var secret = Encoding.ASCII.GetBytes(secretString);
        Console.WriteLine(signature.Algorithm);

        using (HMACSHA512 hmac = new HMACSHA512(secret))
        {
            var storedHash = new byte[hmac.HashSize / 8];
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(timestampAndPayload));
            for (int i = 0; i < storedHash.Length; i++)
            {
                if (computedHash[i] != signature.Hash[i])
                {
                    return false;
                }
            }
        }

        return true;
    }
}

public class WebhookStringPayload
{
    private static IEnumerable<string> FlattenKeyValue(KeyValuePair<string, object> entry)
    {
        var (key, value) = entry;

        if (value is Dictionary<string, object> dict)
        {
            return dict.SelectMany(subEntry =>
                FlattenKeyValue(new KeyValuePair<string, object>($"{key}.{subEntry.Key}", subEntry.Value))
            );
        }
        else if (value is List<object> list)
        {
            return list.SelectMany((element, index) =>
                FlattenKeyValue(new KeyValuePair<string, object>($"{key}[{index}]", element))
            );
        }
        else if (value is List<string> stringList)
        {
            return stringList.SelectMany((element, index) =>
                FlattenKeyValue(new KeyValuePair<string, object>($"{key}[{index}]", element))
            );
        }
        else
        {
            return new[] { $"{key}={PutValue(value)}" };
        }
    }

    public static string ConvertToString(Dictionary<string, object> map)
    {
        if (map is object && !map.GetType().IsArray)
        {
            return string.Join(",",
                map.SelectMany(entry => FlattenKeyValue(new KeyValuePair<string, object>(entry.Key, entry.Value)))
                   .OrderBy(s => s)
            );
        }
        else
        {
            throw new ArgumentException("Input must be a non-null object.");
        }
    }

    private static string PutValue(object value)
    {
        if (value == null)
        {
            return string.Empty;
        }

        return value.ToString();
    }
}



[ApiController]
[Route("[controller]")]
public class WebhookController : ControllerBase
{

    private readonly ILogger<WebhookController> _logger;

    public WebhookController(ILogger<WebhookController> logger)
    {
        _logger = logger;
    }

    [HttpPost(Name = "PostWebhook")]
    public async Task<IActionResult> Post([FromBody] WebhookBodyModel data)
    {
        try
        {

            var signature = "";


            if (!String.IsNullOrEmpty(Request.Headers["x-webhook-signature"]))
            {
                signature = Request.Headers["x-webhook-signature"];
            }

            var jsonData = data.toDictionary(data);

            var payloadString = WebhookStringPayload.ConvertToString(jsonData).ToLower();
            Console.WriteLine(payloadString);

            var verifier = new SignatureVerifier();
            var parser = new SignatureParser();
            var sig = parser.Parse(signature);
            bool isValid = verifier.Verify(sig, "abc123", payloadString.ToLower());
            if (isValid)
            {
                Console.WriteLine("Successfully Verified");
                return Ok("Received and Verified");
            }
            else
            {
                Console.WriteLine("Failed to Verify");
                return StatusCode(200, "Received but not verified");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Internal Server Error");
            return StatusCode(500, $"Internal Server Error: {ex.Message}");
        }
    }
}
