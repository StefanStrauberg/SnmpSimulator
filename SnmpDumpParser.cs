using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace SnmpSimulator;

public enum SnmpValueType
{
    String,
    Integer,
    Gauge32,
    Counter32,
    Counter64,
    TimeTicks,
    IpAddress,
    ObjectIdentifier,
    HexString,
    Opaque,
    Null,
    Unknown
}

public sealed class SnmpValue
{
    public required SnmpValueType Type { get; init; }

    public object? Value { get; init; }

    public string OriginalType { get; init; } = "";
}

public sealed class SnmpEntry
{
    public required string Oid { get; init; }

    public required uint[] OidParts { get; init; }

    public required SnmpValue Value { get; init; }

    public override string ToString()
    {
        return $"{Oid} = {Value.OriginalType}: {Value.Value}";
    }
}

public static class SnmpDumpParser
{
    private static readonly Regex EntryRegex = new(
        @"^(?<oid>\.?(?:iso|ccitt|[0-9]+)(?:\.[0-9]+)*)\s*=\s*(?<type>[A-Za-z0-9_-]+)\s*:\s*(?<value>.*)$",
        RegexOptions.Compiled);

    // Net-SNMP may print an empty OCTET STRING without the `STRING:` prefix:
    //   iso.3.6.1.2.1.2.2.1.6.4 = ""
    // Treat quoted bare values as STRING entries instead of continuation lines.
    private static readonly Regex BareStringEntryRegex = new(
        @"^(?<oid>\.?(?:iso|ccitt|[0-9]+)(?:\.[0-9]+)*)\s*=\s*(?<value>""(?:\\.|[^""])*"")\s*$",
        RegexOptions.Compiled);

    // Used only as a boundary detector: an unrecognized `OID = ...` line
    // must never be appended to the previous multiline value.
    private static readonly Regex EntryStartRegex = new(
        @"^(?<oid>\.?(?:iso|ccitt|[0-9]+)(?:\.[0-9]+)*)\s*=",
        RegexOptions.Compiled);

    public static List<SnmpEntry> Parse(string fileName)
    {
        var lines = File.ReadAllLines(fileName);

        var result = new List<SnmpEntry>();

        string? currentOid = null;
        string? currentType = null;

        var currentValue = new StringBuilder();

        foreach (var line in lines)
        {
            var match = EntryRegex.Match(line);

            if (match.Success)
            {
                FinishCurrent(
                    result,
                    currentOid,
                    currentType,
                    currentValue);

                currentOid = NormalizeOid(
                    match.Groups["oid"].Value);

                currentType =
                    match.Groups["type"].Value;

                currentValue.Clear();

                currentValue.Append(
                    match.Groups["value"].Value);

                continue;
            }

            var bareStringMatch = BareStringEntryRegex.Match(line);

            if (bareStringMatch.Success)
            {
                FinishCurrent(
                    result,
                    currentOid,
                    currentType,
                    currentValue);

                currentOid = NormalizeOid(
                    bareStringMatch.Groups["oid"].Value);

                currentType = "STRING";
                currentValue.Clear();
                currentValue.Append(
                    bareStringMatch.Groups["value"].Value);

                continue;
            }

            var entryStartMatch = EntryStartRegex.Match(line);

            if (entryStartMatch.Success)
            {
                FinishCurrent(
                    result,
                    currentOid,
                    currentType,
                    currentValue);

                Console.WriteLine(
                    $"WARNING: unsupported dump entry syntax: {line}");

                currentOid = null;
                currentType = null;
                currentValue.Clear();
                continue;
            }

            /*
             * Продолжение предыдущего значения.
             *
             * Например:
             *
             * STRING: "Huawei Versatile...
             * VRP ...
             * Copyright ...
             * "
             */
            if (currentOid != null)
            {
                currentValue.AppendLine();
                currentValue.Append(line);
            }
        }

        FinishCurrent(
            result,
            currentOid,
            currentType,
            currentValue);

        return result;
    }

    private static void FinishCurrent(
        ICollection<SnmpEntry> result,
        string? oid,
        string? type,
        StringBuilder value)
    {
        if (oid == null || type == null)
            return;

        try
        {
            result.Add(
                new SnmpEntry
                {
                    Oid = oid,
                    OidParts = ParseOid(oid),
                    Value = ParseValue(type, value.ToString())
                });
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"WARNING: cannot parse {oid}: {ex.Message}");
        }
    }

    private static SnmpValue ParseValue(
        string type,
        string raw)
    {
        return type.ToLowerInvariant() switch
        {
            "string" =>
                new SnmpValue
                {
                    Type = SnmpValueType.String,
                    Value = ParseString(raw),
                    OriginalType = type
                },

            "integer" or "integer32" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Integer,
                    Value = ParseInt32(raw),
                    OriginalType = type
                },

            "gauge32" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Gauge32,
                    Value = ParseUInt32(raw),
                    OriginalType = type
                },

            "unsigned32" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Gauge32,
                    Value = ParseUInt32(raw),
                    OriginalType = type
                },

            "counter32" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Counter32,
                    Value = ParseUInt32(raw),
                    OriginalType = type
                },

            "counter64" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Counter64,
                    Value = ParseUInt64(raw),
                    OriginalType = type
                },

            "timeticks" =>
                new SnmpValue
                {
                    Type = SnmpValueType.TimeTicks,
                    Value = ParseTimeTicks(raw),
                    OriginalType = type
                },

            "ipaddress" =>
                new SnmpValue
                {
                    Type = SnmpValueType.IpAddress,
                    Value = ParseIp(raw),
                    OriginalType = type
                },

            "oid" =>
                new SnmpValue
                {
                    Type = SnmpValueType.ObjectIdentifier,
                    Value = NormalizeOid(
                        RemoveQuotes(raw.Trim())),
                    OriginalType = type
                },

            "hex-string" =>
                new SnmpValue
                {
                    Type = SnmpValueType.HexString,
                    Value = ParseHex(raw),
                    OriginalType = type
                },

            "opaque" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Opaque,
                    Value = ParseHex(raw),
                    OriginalType = type
                },

            "null" =>
                new SnmpValue
                {
                    Type = SnmpValueType.Null,
                    Value = null,
                    OriginalType = type
                },

            _ =>
                ParseUnknown(type, raw)
        };
    }

    private static string ParseString(string value)
    {
        value = value.Trim();

        value = RemoveQuotes(value);

        return value
            .Replace("\\\"", "\"")
            .Replace("\\r", "\r")
            .Replace("\\n", "\n");
    }

    private static int ParseInt32(string value)
    {
        var match =
            Regex.Match(value.Trim(), @"^-?\d+");

        if (!match.Success)
            throw new FormatException(
                $"Invalid integer: {value}");

        return int.Parse(
            match.Value,
            CultureInfo.InvariantCulture);
    }

    private static uint ParseUInt32(string value)
    {
        var match =
            Regex.Match(value.Trim(), @"^\d+");

        if (!match.Success)
            throw new FormatException(
                $"Invalid uint32: {value}");

        return uint.Parse(
            match.Value,
            CultureInfo.InvariantCulture);
    }

    private static ulong ParseUInt64(string value)
    {
        var match =
            Regex.Match(value.Trim(), @"^\d+");

        if (!match.Success)
            throw new FormatException(
                $"Invalid uint64: {value}");

        return ulong.Parse(
            match.Value,
            CultureInfo.InvariantCulture);
    }

    private static uint ParseTimeTicks(string value)
    {
        var match =
            Regex.Match(
                value.Trim(),
                @"^\((\d+)\)");

        if (!match.Success)
            throw new FormatException(
                $"Invalid Timeticks: {value}");

        return uint.Parse(
            match.Groups[1].Value,
            CultureInfo.InvariantCulture);
    }

    private static string ParseIp(string value)
    {
        return RemoveQuotes(value.Trim());
    }

    private static byte[] ParseHex(string value)
    {
        var tokens = value
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries);

        var result = new List<byte>(tokens.Length);

        foreach (var token in tokens)
        {
            if (token.Length != 2 ||
                !byte.TryParse(
                    token,
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out var b))
            {
                throw new FormatException($"Invalid hex byte: {token}");
            }

            result.Add(b);
        }

        return result.ToArray();
    }

    private static SnmpValue ParseUnknown(string type, string raw)
    {
        Console.WriteLine(
            $"WARNING: unsupported SNMP type '{type}', encoding as OCTET STRING.");

        return new SnmpValue
        {
            Type = SnmpValueType.String,
            Value = raw,
            OriginalType = type
        };
    }

    public static uint[] ParseOid(string oid)
    {
        oid = NormalizeOid(oid);

        return oid
            .Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(
                x => uint.Parse(
                    x,
                    CultureInfo.InvariantCulture))
            .ToArray();
    }

    public static string NormalizeOid(string oid)
    {
        oid = oid.Trim();

        if (oid.StartsWith('.'))
            oid = oid[1..];

        if (oid.Equals(
                "iso",
                StringComparison.OrdinalIgnoreCase))
        {
            return "1";
        }

        if (oid.StartsWith(
                "iso.",
                StringComparison.OrdinalIgnoreCase))
        {
            return "1." + oid[4..];
        }

        /*
         * Обычно этого в твоём dump не понадобится,
         * но оставляем поддержку.
         */
        if (oid.StartsWith(
                "ccitt.",
                StringComparison.OrdinalIgnoreCase))
        {
            return "0." + oid[6..];
        }

        return oid;
    }

    private static string RemoveQuotes(string value)
    {
        if (value.Length >= 2 &&
            value[0] == '"' &&
            value[^1] == '"')
        {
            return value[1..^1];
        }

        return value;
    }
}