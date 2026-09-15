using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace SnmpSimulator;

public sealed class BerReader
{
    private readonly byte[] _data;
    private int _position;

    public BerReader(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    public bool End => _position >= _data.Length;

    public byte ReadByte()
    {
        if (End)
            throw new InvalidOperationException("Unexpected end of BER data.");

        return _data[_position++];
    }

    public int ReadLength()
    {
        var first = ReadByte();

        if ((first & 0x80) == 0)
            return first;

        var count = first & 0x7F;

        if (count == 0)
            throw new InvalidOperationException("Indefinite BER length is not supported.");

        if (count > 4)
            throw new InvalidOperationException("BER length is too large.");

        var length = 0;

        for (var i = 0; i < count; i++)
        {
            if (length > (int.MaxValue >> 8))
                throw new InvalidOperationException("BER length overflow.");

            length = (length << 8) | ReadByte();
        }

        return length;
    }

    public byte[] ReadBytes(int length)
    {
        if (length < 0 || length > _data.Length - _position)
            throw new InvalidOperationException("Invalid BER length.");

        var result = new byte[length];
        Buffer.BlockCopy(_data, _position, result, 0, length);
        _position += length;
        return result;
    }

    public BerReader ReadConstructed(byte expectedTag)
    {
        var tag = ReadByte();

        if (tag != expectedTag)
            throw new InvalidOperationException($"Expected tag 0x{expectedTag:X2}, got 0x{tag:X2}");

        return new BerReader(ReadBytes(ReadLength()));
    }

    public byte[] ReadValue(byte expectedTag)
    {
        var tag = ReadByte();

        if (tag != expectedTag)
            throw new InvalidOperationException($"Expected tag 0x{expectedTag:X2}, got 0x{tag:X2}");

        return ReadBytes(ReadLength());
    }

    public int ReadInt32()
    {
        var bytes = ReadValue(0x02);

        if (bytes.Length == 0 || bytes.Length > 4)
            throw new InvalidOperationException("Invalid INTEGER.");

        // Decode directly into a signed Int32. Starting with -1 for a negative
        // value provides sign extension without a problematic << 32 operation.
        var value = (bytes[0] & 0x80) != 0 ? -1 : 0;

        foreach (var b in bytes)
            value = (value << 8) | b;

        return value;
    }

    public uint ReadUInt32(byte expectedTag)
    {
        var bytes = ReadValue(expectedTag);

        // Application-wide unsigned SNMP values are encoded like INTEGER and
        // may contain one leading 0x00 to keep the value positive.
        if (bytes.Length == 0 || bytes.Length > 5 ||
            (bytes.Length == 5 && bytes[0] != 0))
        {
            throw new InvalidOperationException("Invalid UInt32.");
        }

        uint value = 0;
        foreach (var b in bytes)
            value = (value << 8) | b;

        return value;
    }

    public ulong ReadUInt64(byte expectedTag)
    {
        var bytes = ReadValue(expectedTag);

        if (bytes.Length == 0 || bytes.Length > 9 ||
            (bytes.Length == 9 && bytes[0] != 0))
        {
            throw new InvalidOperationException("Invalid UInt64.");
        }

        ulong value = 0;
        foreach (var b in bytes)
            value = (value << 8) | b;

        return value;
    }

    public string ReadString() => Encoding.UTF8.GetString(ReadValue(0x04));

    public byte[] ReadOctetString() => ReadValue(0x04);

    public string ReadOid()
    {
        var bytes = ReadValue(0x06);

        if (bytes.Length == 0)
            throw new InvalidOperationException("Invalid OID.");

        var offset = 0;
        var firstCombined = ReadBase128(bytes, ref offset);

        uint firstPart;
        uint secondPart;

        if (firstCombined < 40)
        {
            firstPart = 0;
            secondPart = firstCombined;
        }
        else if (firstCombined < 80)
        {
            firstPart = 1;
            secondPart = firstCombined - 40;
        }
        else
        {
            firstPart = 2;
            secondPart = firstCombined - 80;
        }

        var parts = new List<uint> { firstPart, secondPart };

        while (offset < bytes.Length)
            parts.Add(ReadBase128(bytes, ref offset));

        return string.Join(".", parts);
    }

    private static uint ReadBase128(byte[] bytes, ref int offset)
    {
        uint value = 0;
        var count = 0;

        while (true)
        {
            if (offset >= bytes.Length)
                throw new InvalidOperationException("Truncated OID subidentifier.");

            var b = bytes[offset++];
            count++;

            // A uint needs at most five base-128 octets, and the fifth may only
            // contribute the low four data bits.
            if (count > 5 || (count == 5 && (value & 0xFE000000) != 0))
                throw new InvalidOperationException("OID subidentifier is too large.");

            if (value > (uint.MaxValue >> 7))
                throw new InvalidOperationException("OID subidentifier overflow.");

            value = (value << 7) | (uint)(b & 0x7F);

            if ((b & 0x80) == 0)
                return value;
        }
    }
}

public static class Ber
{
    public static byte[] Length(int length)
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        if (length < 128)
            return new[] { (byte)length };

        var bytes = new List<byte>();
        var value = length;

        while (value > 0)
        {
            bytes.Insert(0, (byte)(value & 0xFF));
            value >>= 8;
        }

        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }

    public static byte[] Tlv(byte tag, byte[] value)
    {
        using var stream = new MemoryStream();
        stream.WriteByte(tag);

        var length = Length(value.Length);
        stream.Write(length, 0, length.Length);
        stream.Write(value, 0, value.Length);
        return stream.ToArray();
    }

    public static byte[] Sequence(params byte[][] values) =>
        Tlv(0x30, Combine(values));

    public static byte[] Integer(int value)
    {
        var bytes = BitConverter.GetBytes(value);

        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        var start = 0;

        while (start < bytes.Length - 1)
        {
            if (bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0)
            {
                start++;
                continue;
            }

            if (bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0)
            {
                start++;
                continue;
            }

            break;
        }

        return Tlv(0x02, bytes[start..]);
    }

    public static byte[] UInt32(byte tag, uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return Tlv(tag, TrimUnsigned(bytes));
    }

    public static byte[] UInt64(byte tag, ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return Tlv(tag, TrimUnsigned(bytes));
    }

    public static byte[] OctetString(string value) =>
        Tlv(0x04, Encoding.UTF8.GetBytes(value));

    public static byte[] OctetString(byte[] value) => Tlv(0x04, value);

    public static byte[] IpAddress(string ip)
    {
        var address = System.Net.IPAddress.Parse(ip);

        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException($"SNMP IpAddress must be IPv4: {ip}");

        return Tlv(0x40, address.GetAddressBytes());
    }

    public static byte[] ObjectIdentifier(string oid)
    {
        var parts = SnmpDumpParser.ParseOid(oid);

        if (parts.Length < 2 || parts[0] > 2 ||
            (parts[0] < 2 && parts[1] > 39))
        {
            throw new InvalidOperationException($"Invalid OID: {oid}");
        }

        using var stream = new MemoryStream();

        var first = checked(parts[0] * 40u + parts[1]);
        WriteBase128(stream, first);

        for (var i = 2; i < parts.Length; i++)
            WriteBase128(stream, parts[i]);

        return Tlv(0x06, stream.ToArray());
    }

    public static byte[] Null() => new byte[] { 0x05, 0x00 };

    public static byte[] NoSuchObject() => Tlv(0x80, Array.Empty<byte>());

    public static byte[] NoSuchInstance() => Tlv(0x81, Array.Empty<byte>());

    public static byte[] EndOfMibView() => Tlv(0x82, Array.Empty<byte>());

    private static void WriteBase128(Stream stream, uint value)
    {
        if (value == 0)
        {
            stream.WriteByte(0);
            return;
        }

        Span<byte> buffer = stackalloc byte[5];
        var index = buffer.Length;

        while (value > 0)
        {
            buffer[--index] = (byte)(value & 0x7F);
            value >>= 7;
        }

        for (var i = index; i < buffer.Length - 1; i++)
            buffer[i] |= 0x80;

        stream.Write(buffer[index..]);
    }

    private static byte[] TrimUnsigned(byte[] bytes)
    {
        var index = 0;

        while (index < bytes.Length - 1 && bytes[index] == 0)
            index++;

        var result = bytes[index..];

        if ((result[0] & 0x80) == 0)
            return result;

        var withZero = new byte[result.Length + 1];
        Buffer.BlockCopy(result, 0, withZero, 1, result.Length);
        return withZero;
    }

    private static byte[] Combine(IEnumerable<byte[]> arrays)
    {
        using var stream = new MemoryStream();

        foreach (var array in arrays)
            stream.Write(array, 0, array.Length);

        return stream.ToArray();
    }
}
