using System.Net;
using System.Net.Sockets;

namespace SnmpSimulator;

public sealed class SnmpServer
{
    private const int MaxBulkRepetitions = 100;
    private const int MaxResponseDatagramSize = 60_000;

    private readonly MibStore _mib;
    private readonly string _community;
    private readonly UdpClient _udp;
    private bool _running;

    public SnmpServer(MibStore mib, string address, int port, string community)
    {
        _mib = mib;
        _community = community;

        if (!IPAddress.TryParse(address, out var ip))
            throw new ArgumentException($"Invalid listen address: {address}", nameof(address));

        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535.");

        _udp = new UdpClient(new IPEndPoint(ip, port));
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _running = true;
        Console.WriteLine("SNMP server started.");
        Console.WriteLine();

        while (_running && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                var result = await _udp.ReceiveAsync(cancellationToken);
                await ProcessRequest(result.Buffer, result.RemoteEndPoint);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }
    }

    public void Stop()
    {
        _running = false;
        _udp.Close();
    }

    private async Task ProcessRequest(byte[] request, IPEndPoint remote)
    {
        try
        {
            var reader = new BerReader(request);
            var message = reader.ReadConstructed(0x30);

            var version = message.ReadInt32();
            var community = message.ReadString();

            if (community != _community)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Rejected community from {remote}");
                return;
            }

            // SNMP version field: 0 = v1, 1 = v2c.
            if (version != 1)
            {
                Console.WriteLine($"Unsupported SNMP version: {version}");
                return;
            }

            var pduTag = message.ReadByte();
            var pduLength = message.ReadLength();
            var pdu = new BerReader(message.ReadBytes(pduLength));
            var requestId = pdu.ReadInt32();

            byte[] responsePdu;
            string operation;

            switch (pduTag)
            {
                case 0xA0:
                    responsePdu = HandleGet(pdu, requestId);
                    operation = "GET";
                    break;

                case 0xA1:
                    responsePdu = HandleGetNext(pdu, requestId);
                    operation = "GETNEXT";
                    break;

                case 0xA5:
                    responsePdu = HandleGetBulk(pdu, requestId);
                    operation = "GETBULK";
                    break;

                default:
                    Console.WriteLine($"Unsupported PDU: 0x{pduTag:X2}");
                    return;
            }

            var response = BuildMessage(community, responsePdu);

            // Avoid oversized UDP datagrams. RFC 3416 defines error-status=tooBig (1).
            if (response.Length > MaxResponseDatagramSize)
            {
                responsePdu = BuildResponsePdu(requestId, 1, 0, Array.Empty<byte[]>());
                response = BuildMessage(community, responsePdu);
            }

            await _udp.SendAsync(response, response.Length, remote);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {operation} from {remote}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Invalid SNMP packet from {remote}: {ex.Message}");
        }
    }

    private byte[] HandleGet(BerReader pdu, int requestId)
    {
        // error-status and error-index in a request must be zero. Read them, but
        // never reflect untrusted request values back into the response.
        _ = pdu.ReadInt32();
        _ = pdu.ReadInt32();

        var variableBindings = ReadVariableBindings(pdu);
        var responseVariables = new List<byte[]>(variableBindings.Count);

        foreach (var variable in variableBindings)
        {
            var entry = _mib.Get(variable.Oid);

            responseVariables.Add(
                entry == null
                    ? BuildVariable(variable.Oid, Ber.NoSuchObject())
                    : BuildVariable(entry.Oid, EncodeValue(entry.Value)));
        }

        return BuildResponsePdu(requestId, 0, 0, responseVariables);
    }

    private byte[] HandleGetNext(BerReader pdu, int requestId)
    {
        _ = pdu.ReadInt32();
        _ = pdu.ReadInt32();

        var variableBindings = ReadVariableBindings(pdu);
        var responseVariables = new List<byte[]>(variableBindings.Count);

        foreach (var variable in variableBindings)
        {
            var entry = _mib.GetNext(variable.Oid);

            responseVariables.Add(
                entry == null
                    ? BuildVariable(variable.Oid, Ber.EndOfMibView())
                    : BuildVariable(entry.Oid, EncodeValue(entry.Value)));
        }

        return BuildResponsePdu(requestId, 0, 0, responseVariables);
    }

    private byte[] HandleGetBulk(BerReader pdu, int requestId)
    {
        var nonRepeaters = Math.Max(0, pdu.ReadInt32());
        var requestedRepetitions = Math.Max(0, pdu.ReadInt32());
        var maxRepetitions = Math.Min(requestedRepetitions, MaxBulkRepetitions);
        var variables = ReadVariableBindings(pdu);

        nonRepeaters = Math.Min(nonRepeaters, variables.Count);

        var result = new List<byte[]>();

        // RFC 3416: non-repeaters are processed once with GETNEXT semantics.
        for (var i = 0; i < nonRepeaters; i++)
        {
            var entry = _mib.GetNext(variables[i].Oid);

            result.Add(
                entry == null
                    ? BuildVariable(variables[i].Oid, Ber.EndOfMibView())
                    : BuildVariable(entry.Oid, EncodeValue(entry.Value)));
        }

        var repeaterCount = variables.Count - nonRepeaters;
        if (repeaterCount == 0 || maxRepetitions == 0)
            return BuildResponsePdu(requestId, 0, 0, result);

        var currentOids = new string[repeaterCount];
        var ended = new bool[repeaterCount];

        for (var i = 0; i < repeaterCount; i++)
            currentOids[i] = variables[nonRepeaters + i].Oid;

        // GETBULK response order is repetition-major:
        // rep1(var1), rep1(var2), rep2(var1), rep2(var2), ...
        for (var repetition = 0; repetition < maxRepetitions; repetition++)
        {
            var allEnded = true;

            for (var i = 0; i < repeaterCount; i++)
            {
                if (ended[i])
                {
                    result.Add(BuildVariable(currentOids[i], Ber.EndOfMibView()));
                    continue;
                }

                var entry = _mib.GetNext(currentOids[i]);

                if (entry == null)
                {
                    ended[i] = true;
                    result.Add(BuildVariable(currentOids[i], Ber.EndOfMibView()));
                    continue;
                }

                allEnded = false;
                currentOids[i] = entry.Oid;
                result.Add(BuildVariable(entry.Oid, EncodeValue(entry.Value)));
            }

            // Once every repeater has reached endOfMibView, additional identical
            // rows add no useful information and may be omitted by the agent.
            if (allEnded)
                break;
        }

        return BuildResponsePdu(requestId, 0, 0, result);
    }

    private static List<(string Oid, byte[] Value)> ReadVariableBindings(BerReader pdu)
    {
        var listReader = pdu.ReadConstructed(0x30);
        var result = new List<(string, byte[])>();

        while (!listReader.End)
        {
            var variable = listReader.ReadConstructed(0x30);
            var oid = variable.ReadOid();
            _ = variable.ReadByte(); // request value tag
            var valueLength = variable.ReadLength();
            var value = variable.ReadBytes(valueLength);

            if (!variable.End)
                throw new InvalidOperationException("Unexpected data after variable binding value.");

            result.Add((oid, value));
        }

        return result;
    }

    private static byte[] BuildResponsePdu(
        int requestId,
        int errorStatus,
        int errorIndex,
        IEnumerable<byte[]> variables)
    {
        var variableBindings = Ber.Sequence(variables.ToArray());

        return Ber.Tlv(
            0xA2,
            Combine(
                Ber.Integer(requestId),
                Ber.Integer(errorStatus),
                Ber.Integer(errorIndex),
                variableBindings));
    }

    private static byte[] BuildVariable(string oid, byte[] value) =>
        Ber.Sequence(Ber.ObjectIdentifier(oid), value);

    private static byte[] BuildMessage(string community, byte[] pdu) =>
        Ber.Sequence(Ber.Integer(1), Ber.OctetString(community), pdu);

    private static byte[] EncodeValue(SnmpValue value)
    {
        return value.Type switch
        {
            SnmpValueType.String => Ber.OctetString((string)value.Value!),
            SnmpValueType.Integer => Ber.Integer((int)value.Value!),
            SnmpValueType.Gauge32 => Ber.UInt32(0x42, (uint)value.Value!),
            SnmpValueType.Counter32 => Ber.UInt32(0x41, (uint)value.Value!),
            SnmpValueType.Counter64 => Ber.UInt64(0x46, (ulong)value.Value!),
            SnmpValueType.TimeTicks => Ber.UInt32(0x43, (uint)value.Value!),
            SnmpValueType.IpAddress => Ber.IpAddress((string)value.Value!),
            SnmpValueType.ObjectIdentifier => Ber.ObjectIdentifier((string)value.Value!),
            SnmpValueType.HexString => Ber.OctetString((byte[])value.Value!),
            SnmpValueType.Opaque => Ber.Tlv(0x44, (byte[])value.Value!),
            SnmpValueType.Null => Ber.Null(),
            _ => Ber.OctetString(value.Value?.ToString() ?? "")
        };
    }

    private static byte[] Combine(params byte[][] arrays)
    {
        using var stream = new MemoryStream();

        foreach (var array in arrays)
            stream.Write(array, 0, array.Length);

        return stream.ToArray();
    }
}
