namespace SnmpSimulator;

public sealed class MibStore
{
    private readonly List<SnmpEntry> _entries;
    private readonly Dictionary<string, SnmpEntry> _byOid;

    public MibStore(IEnumerable<SnmpEntry> entries)
    {
        _entries = entries
            .GroupBy(x => x.Oid, StringComparer.Ordinal)
            .Select(x => x.First())
            .OrderBy(x => x.OidParts, OidComparer.Instance)
            .ToList();

        _byOid = _entries.ToDictionary(x => x.Oid, StringComparer.Ordinal);
    }

    public int Count => _entries.Count;

    public SnmpEntry? Get(string oid)
    {
        var normalized = SnmpDumpParser.NormalizeOid(oid);
        return _byOid.GetValueOrDefault(normalized);
    }

    public SnmpEntry? GetNext(string oid)
    {
        var parts = SnmpDumpParser.ParseOid(oid);
        var low = 0;
        var high = _entries.Count;

        // Upper-bound search: first OID strictly greater than the requested OID.
        while (low < high)
        {
            var mid = low + ((high - low) / 2);
            var comparison = OidComparer.Instance.Compare(_entries[mid].OidParts, parts);

            if (comparison <= 0)
                low = mid + 1;
            else
                high = mid;
        }

        return low < _entries.Count ? _entries[low] : null;
    }

    public IReadOnlyList<SnmpEntry> Entries => _entries;
}

public sealed class OidComparer : IComparer<uint[]>
{
    public static readonly OidComparer Instance = new();

    public int Compare(uint[]? x, uint[]? y)
    {
        if (ReferenceEquals(x, y))
            return 0;
        if (x == null)
            return -1;
        if (y == null)
            return 1;

        var count = Math.Min(x.Length, y.Length);

        for (var i = 0; i < count; i++)
        {
            var comparison = x[i].CompareTo(y[i]);
            if (comparison != 0)
                return comparison;
        }

        return x.Length.CompareTo(y.Length);
    }
}
