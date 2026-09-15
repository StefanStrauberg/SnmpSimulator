using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SnmpSimulator;

public static class Program
{
    public static async Task Main(string[] args)
    {
        Options options;

        try
        {
            options = ParseArguments(args);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Argument error: {ex.Message}");
            Console.WriteLine();
            PrintHelp();
            return;
        }

        if (options.Help || string.IsNullOrWhiteSpace(options.File))
        {
            PrintHelp();
            return;
        }

        if (!File.Exists(options.File))
        {
            Console.WriteLine($"File not found: {options.File}");
            return;
        }

        Console.WriteLine();
        Console.WriteLine("========================================");
        Console.WriteLine("          SNMP DUMP SIMULATOR");
        Console.WriteLine("========================================");
        Console.WriteLine();
        Console.WriteLine($"Dump:       {Path.GetFullPath(options.File)}");
        Console.WriteLine($"Address:    {options.Address}");
        Console.WriteLine($"Port:       {options.Port}");
        Console.WriteLine($"Community:  {options.Community}");
        Console.WriteLine();
        Console.WriteLine("Loading dump...");

        var entries = SnmpDumpParser.Parse(options.File);
        Console.WriteLine($"Loaded entries: {entries.Count}");

        if (entries.Count == 0)
        {
            Console.WriteLine("No SNMP entries found.");
            return;
        }

        var mib = new MibStore(entries);
        Console.WriteLine($"MIB objects:    {mib.Count}");
        Console.WriteLine();

        SnmpServer server;
        try
        {
            server = new SnmpServer(mib, options.Address, options.Port, options.Community);
        }
        catch (Exception ex) when (ex is ArgumentException or SocketException)
        {
            Console.WriteLine($"Cannot start server: {ex.Message}");
            return;
        }

        using var cts = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            server.Stop();
        };

        Console.WriteLine($"Listening on {options.Address}:{options.Port}");
        Console.WriteLine();
        Console.WriteLine("Test:");
        Console.WriteLine();
        Console.WriteLine($"  snmpwalk -v2c -c {options.Community} {options.Address}:{options.Port}");
        Console.WriteLine();
        Console.WriteLine("Press Ctrl+C to stop.");
        Console.WriteLine();

        try
        {
            await server.RunAsync(cts.Token);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fatal error: {ex}");
        }
    }

    private static Options ParseArguments(string[] args)
    {
        var result = new Options();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--file":
                case "-f":
                    result.File = Next(args, ref i);
                    break;

                case "--address":
                case "-a":
                    result.Address = Next(args, ref i);
                    if (!IPAddress.TryParse(result.Address, out _))
                        throw new ArgumentException($"Invalid IP address: {result.Address}");
                    break;

                case "--port":
                case "-p":
                {
                    var rawPort = Next(args, ref i);
                    if (!int.TryParse(rawPort, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
                        port is < 1 or > 65535)
                    {
                        throw new ArgumentException($"Invalid UDP port: {rawPort}. Expected 1..65535.");
                    }

                    result.Port = port;
                    break;
                }

                case "--community":
                case "-c":
                    result.Community = Next(args, ref i);
                    break;

                case "--help":
                case "-h":
                    result.Help = true;
                    break;

                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        return result;
    }

    private static string Next(string[] args, ref int index)
    {
        if (index + 1 >= args.Length)
            throw new ArgumentException($"Missing value after {args[index]}");

        return args[++index];
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            SNMP Dump Simulator

            Usage:

              dotnet run -- \
                --file dump.txt \
                --address 127.0.0.1 \
                --port 1161 \
                --community public

            Options:

              -f, --file
                  SNMP walk dump file (prefer numeric OIDs from snmpwalk -On)

              -a, --address
                  IP address to listen on (default: 127.0.0.1)

              -p, --port
                  UDP port, 1..65535 (default: 1161)

              -c, --community
                  SNMP v2c community (default: public)

              -h, --help
                  Show help
            """);
    }
}

public sealed class Options
{
    public string? File { get; set; }
    public string Address { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 1161;
    public string Community { get; set; } = "public";
    public bool Help { get; set; }
}
