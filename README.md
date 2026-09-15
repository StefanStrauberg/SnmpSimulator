# SNMP Dump Simulator

Small SNMP v2c UDP simulator for replaying values from a numeric `snmpwalk` dump.

## Requirements

- .NET 9 SDK
- Net-SNMP tools are optional, but useful for creating dumps and testing.

## Create a dump

Use numeric OIDs so the simulator does not need MIB files to resolve symbolic names:

```bash
snmpwalk -v2c -c public -On 192.0.2.10 > dump.txt
```

Both of these numeric forms are accepted:

```text
.1.3.6.1.2.1.1.1.0 = STRING: "Example device"
1.3.6.1.2.1.1.3.0 = Timeticks: (12345) 0:02:03.45
```

`iso.3.6...` and `ccitt...` are also accepted. Symbolic OIDs such as
`SNMPv2-MIB::sysDescr.0` are not resolved; create the dump with `-On`.

## Run

```bash
dotnet run -- \
  --file dump.txt \
  --address 127.0.0.1 \
  --port 1161 \
  --community public
```

Defaults:

- address: `127.0.0.1`
- port: `1161`
- community: `public`

## Test

```bash
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1
snmpbulkwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1
```

## Supported operations

- SNMP v2c GET
- SNMP v2c GETNEXT
- SNMP v2c GETBULK

GETBULK repetitions are capped at 100 per request to avoid excessive memory/CPU
use from untrusted UDP packets. Responses larger than 60,000 bytes are replaced
with a standard SNMP `tooBig` response.

## Supported dump value types

- STRING
- INTEGER / INTEGER32
- Gauge32 / Unsigned32
- Counter32
- Counter64
- Timeticks
- IpAddress (IPv4 only, as required by SNMP IpAddress syntax)
- OID
- Hex-STRING
- Opaque (hex bytes)
- NULL

Unknown value types are preserved as OCTET STRING and produce a warning.

## Notes

This is a dump-driven simulator, not a full MIB engine. It cannot reliably
distinguish `noSuchObject` from `noSuchInstance` without MIB schema information,
so a missing exact GET is represented as `noSuchObject`. GETNEXT/GETBULK use
`endOfMibView` when no lexicographic successor exists.

## Running in Docker, at a real router's IP

The API always talks SNMP on port 161 to whatever IP a network device record
holds (see `SNMPCommandExecutor.cs`) - there's no separate "test port" to
point it at instead. So to exercise the real API code path against a stand-in
router, the simulator needs to actually answer at that router's IP, not just
on localhost.

`docker-compose.snmp.yml` (repo root) does this: it runs one simulator
container per simulated device, each pinned via Docker networking to a static
IP on the same `192.168.101.0/24` network the API container is attached to in
`docker-compose.yml` - the production router subnet, reachable from this repo's
own Docker network only. This only works because that subnet isn't otherwise
reachable from the machine running Docker; see the comment above the `app-net`
network definition in `docker-compose.yml`.

```bash
# 1. Bring up the app once, so the shared network exists.
docker compose up -d

# 2. Bring up just the simulated router(s) you need right now.
docker compose -f docker-compose.snmp.yml up -d --build router-8

# 3. Point the app at 192.168.101.8 (SNMP port 161, community "public") the
#    same way you'd point it at a real device - e.g. via
#    POST /api/v1/NetworkDevices with that IP.

# 4. Done testing - tear the simulators down (the app keeps running).
docker compose -f docker-compose.snmp.yml down
```

Dump files live in `dumps/` and are bind-mounted into the container read-only,
so swapping a dump doesn't require rebuilding the image - just restart the
service. `dumps/router-8.example.txt` is a minimal starter (sysDescr/sysName/
etc. only); for anything beyond a basic reachability check, capture a real
dump per the instructions above (`snmpwalk -On ...`) against the actual
router you're standing in for, and point `--file` at it. Real dumps are
git-ignored by default (see the repo's `.gitignore`) since they can reveal
internal topology/ARP/MAC data.

To add another simulated device, copy the commented-out template service in
`docker-compose.snmp.yml` and give it a free IP in `192.168.101.0/24` (any
address but `.1`, the network's gateway) and its own dump file.
