using System.Reflection;
using System.Collections.Concurrent;
using BPSR_ZDPSLib;
using Google.Protobuf;

namespace BPSR_ZDPSRecorder;

/// <summary>
/// Turns the numeric service / method ids into the names ZDPSLib knows them by and, where the protobuf type can be inferred
/// from the method name, decodes the payload to JSON. Everything it produces is derived data: it can be refreshed any time by
/// regenerating the database from the pcap files.
/// </summary>
public sealed class NameResolver
{
    private static readonly Assembly LibAssembly = typeof(EServiceId).Assembly;
    private const string MethodsNamespace = "BPSR_ZDPSLib.ServiceMethods.";

    private readonly ConcurrentDictionary<(string Service, bool Proxy), Type?> _methodEnums = new();
    private readonly Lazy<Dictionary<string, List<Type>>> _protoTypes = new(BuildProtoTypeIndex);
    private readonly ConcurrentDictionary<(string Service, string Method, bool Return), Type?> _payloadTypes = new();
    private readonly ConcurrentDictionary<Type, MessageParser?> _parsers = new();

    public (string? Service, string? Method) Resolve(ulong? serviceId, uint? methodId, bool serverToClientNotify)
    {
        if (serviceId == null)
            return (null, null);

        // A server notify uses the notify service ids, everything else the proxy (RPC) ones; fall back to the other table as the id spaces overlap
        string? serviceName = null;
        bool proxy = !serverToClientNotify;
        for (var attempt = 0; attempt < 2 && serviceName == null; attempt++)
        {
            serviceName = proxy ? ProxyServiceName(serviceId.Value) : NotifyServiceName(serviceId.Value);
            if (serviceName == null)
                proxy = !proxy;
        }

        if (serviceName == null || methodId == null)
            return (serviceName, null);

        return (serviceName, MethodName(serviceName, proxy, methodId.Value));
    }

    private static string? NotifyServiceName(ulong id) => Enum.IsDefined(typeof(EServiceId), id) ? Enum.GetName(typeof(EServiceId), id) : null;

    private static string? ProxyServiceName(ulong id) =>
        id <= uint.MaxValue && Enum.IsDefined(typeof(EProxyServiceId), (uint)id) ? Enum.GetName(typeof(EProxyServiceId), (uint)id) : null;

    private string? MethodName(string serviceName, bool proxy, uint methodId)
    {
        var enumType = _methodEnums.GetOrAdd((serviceName, proxy), key =>
        {
            string[] candidates = key.Proxy ? [key.Service + "Proxy"] : [key.Service, key.Service.EndsWith("Ntf") ? key.Service[..^3] : key.Service];
            foreach (var candidate in candidates)
            {
                var type = LibAssembly.GetType(MethodsNamespace + candidate);
                if (type is { IsEnum: true })
                    return type;
            }
            return null;
        });

        if (enumType == null || methodId > int.MaxValue)
            return null;

        return Enum.GetName(enumType, (int)methodId);
    }

    /// <summary>
    /// Decodes the payload when a protobuf type named after the method exists: notifies use "{Method}", calls and returns the
    /// service's wrappers "{Service}.{Method}" / "{Service}.{Method}_Ret", falling back to "{Method}Request" / "{Method}Reply"
    /// (inside the container that is named like the service when the name is ambiguous).
    /// </summary>
    public string? TryDecode(string? service, string? method, MsgTypeId kind, ReadOnlySpan<byte> payload)
    {
        if (service == null || method == null || payload.IsEmpty)
            return null;

        bool isReturn = kind == MsgTypeId.Return;
        var type = _payloadTypes.GetOrAdd((service, method, isReturn), key => FindPayloadType(key.Service, key.Method, kind));
        if (type == null)
            return null;

        var parser = _parsers.GetOrAdd(type, t => (MessageParser?)t.GetProperty("Parser", BindingFlags.Public | BindingFlags.Static)?.GetValue(null));
        if (parser == null)
            return null;

        // Return payloads were seen with a few bytes in front of the protobuf (ZDPS looks for the 0x0A tag of field 1)
        var data = payload.ToArray();
        for (var skip = 0; skip <= Math.Min(3, data.Length - 1); skip++)
        {
            if (skip > 0 && (!isReturn || data[skip] != 0x0A))
                continue;

            try
            {
                var message = parser.ParseFrom(data, skip, data.Length - skip);
                return JsonFormatter.Default.Format(message);
            }
            catch (Exception)
            {
                // Not only InvalidProtocolBufferException: formatting can throw as well (e.g. Any fields), and decoding is best effort
            }
        }

        return null;
    }

    private Type? FindPayloadType(string service, string method, MsgTypeId kind)
    {
        var index = _protoTypes.Value;
        // The service name as used in the generated containers: "WorldNtf" for notifies, "World" for the "WorldProxy" / "World" RPC service
        var containerName = service;

        // RPC calls and returns are the service's own wrapper messages: {Service}.Types.{Method} holds the arguments (often a single
        // VRequest field with the {Method}Request), {Service}.Types.{Method}_Ret the result (field Ret). Only taken from the service's
        // container, since other services define messages of the same name.
        var wrapperName = kind switch
        {
            MsgTypeId.Call => method,
            MsgTypeId.Return => method + "_Ret",
            _ => null,
        };
        if (wrapperName != null && index.TryGetValue(wrapperName, out var wrappers))
        {
            var wrapper = wrappers.Where(t => IsInContainer(t, containerName)).ToList();
            if (wrapper.Count == 1)
                return wrapper[0];
        }

        string[] names = kind switch
        {
            MsgTypeId.Call => [method + "Request", method],
            MsgTypeId.Return => [method + "Reply", method + "Return", method + "Response"],
            _ => [method],
        };

        foreach (var name in names)
        {
            if (!index.TryGetValue(name, out var candidates))
                continue;

            if (candidates.Count == 1)
                return candidates[0];

            // Generated as {Container}.Types.{Message}, the container being called like the service (optionally with a "Csharp" suffix)
            var inService = candidates.Where(t => IsInContainer(t, containerName)).ToList();
            if (inService.Count == 1)
                return inService[0];
        }

        return null;
    }

    private static bool IsInContainer(Type type, string containerName) =>
        type.DeclaringType?.DeclaringType?.Name is { } container && (container == containerName || container == containerName + "Csharp");

    private static Dictionary<string, List<Type>> BuildProtoTypeIndex()
    {
        var index = new Dictionary<string, List<Type>>();
        foreach (var type in LibAssembly.GetTypes())
        {
            if (!type.IsClass || type.IsAbstract || !typeof(IMessage).IsAssignableFrom(type))
                continue;

            if (!index.TryGetValue(type.Name, out var list))
                index[type.Name] = list = [];
            list.Add(type);
        }
        return index;
    }
}
