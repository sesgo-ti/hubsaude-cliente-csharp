// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;

namespace HubSaude.Cliente.Tests.ArchRules;

/// <summary>
/// Fitness functions equivalentes às <c>ClientArchRules</c> do cliente Java
/// (ADR-15 / ADR-70), sem dependência extra: reflexão + metadados do PE.
/// </summary>
internal static class ClientArchRules
{
    internal const string ProductionNamespace = "HubSaude.Cliente";

    internal static readonly string[] AllowedPublicTypeNames =
    [
        "HubSaude.Cliente.CertificateValidator",
        "HubSaude.Cliente.FaultToleranceConfig",
        "HubSaude.Cliente.ISigningStrategy",
        "HubSaude.Cliente.PemLoader",
        "HubSaude.Cliente.PrivateKeySigningStrategy",
        "HubSaude.Cliente.PssParameters",
        "HubSaude.Cliente.SigningException",
        "HubSaude.Cliente.SigningStrategyFactory",
        "HubSaude.Cliente.SmartTokenClient",
        "HubSaude.Cliente.SmartTokenClient+TokenResponse",
        "HubSaude.Cliente.SmartTokenClientBuilder",
        "HubSaude.Cliente.SmartTokenException",
    ];

    private static readonly string[] ForbiddenTypeNamespacePrefixes =
    [
        "Microsoft.AspNetCore",
        "Microsoft.EntityFrameworkCore",
        "Newtonsoft.Json",
        "NHibernate",
        "Confluent.Kafka",
        "Spring",
        "System.Data",
        "System.Web",
        "ca.uhn.hapi",
    ];

    private static readonly string[] AllowedThirdPartyAssemblies =
    [
        "BouncyCastle.Cryptography",
        "Microsoft.Extensions.Logging.Abstractions",
    ];

    internal static Assembly ProductionAssembly => typeof(SmartTokenClient).Assembly;

    internal static IReadOnlyList<Type> PublicTypes()
    {
        return ProductionAssembly
            .GetTypes()
            .Where(t => t.IsPublic || t.IsNestedPublic)
            .ToArray();
    }

    internal static IEnumerable<string> UnexpectedPublicTypes()
    {
        var allowed = new HashSet<string>(AllowedPublicTypeNames, StringComparer.Ordinal);
        foreach (var type in PublicTypes())
        {
            var name = type.FullName ?? type.Name;
            if (name.StartsWith("Coverlet.", StringComparison.Ordinal)
                || (type.Namespace is { } ns && ns.StartsWith("Coverlet.", StringComparison.Ordinal)))
            {
                continue;
            }

            if (!allowed.Contains(name))
            {
                yield return name;
            }
        }
    }

    internal static IEnumerable<string> OpenPublicTypes()
    {
        foreach (var type in PublicTypes())
        {
            if (type.IsInterface || type.IsEnum || type.IsAbstract || type.IsSealed)
            {
                continue;
            }

            yield return type.FullName ?? type.Name;
        }
    }

    internal static IEnumerable<string> TypesOutsideProductionNamespace()
    {
        return ProductionAssembly.GetTypes()
            .Where(t => t.GetCustomAttribute<CompilerGeneratedAttribute>() is null)
            .Where(IsAuthoredTypeOutsideProductionNamespace)
            .Select(t => t.FullName ?? t.Name);
    }

    private static bool IsAuthoredTypeOutsideProductionNamespace(Type type)
    {
        var ns = type.Namespace;
        if (string.IsNullOrEmpty(ns)
            || ns.StartsWith("System.", StringComparison.Ordinal)
            || ns.StartsWith("Microsoft.", StringComparison.Ordinal)
            || ns.StartsWith("Coverlet.", StringComparison.Ordinal))
        {
            return false;
        }

        return ns != ProductionNamespace;
    }

    internal static IEnumerable<string> UnexpectedInternalsVisibleTo()
    {
        var attrs = ProductionAssembly.GetCustomAttributes<InternalsVisibleToAttribute>();
        foreach (var attr in attrs)
        {
            if (!string.Equals(attr.AssemblyName, "HubSaude.Cliente.Tests", StringComparison.Ordinal))
            {
                yield return attr.AssemblyName;
            }
        }
    }

    internal static IEnumerable<string> UnexpectedAssemblyReferences()
    {
        foreach (var name in ProductionAssembly.GetReferencedAssemblies())
        {
            var simple = name.Name ?? string.Empty;
            if (simple.StartsWith("System", StringComparison.Ordinal)
                || simple.StartsWith("Microsoft.CSharp", StringComparison.Ordinal)
                || simple.StartsWith("netstandard", StringComparison.Ordinal)
                || simple.StartsWith("mscorlib", StringComparison.Ordinal)
                || simple.StartsWith("Coverlet.", StringComparison.Ordinal)
                || AllowedThirdPartyAssemblies.Contains(simple, StringComparer.Ordinal))
            {
                continue;
            }

            yield return simple;
        }
    }

    internal static IEnumerable<string> ForbiddenTypeReferences()
    {
        foreach (var fullName in ReferencedTypeFullNames())
        {
            if (string.Equals(fullName, "System.Console", StringComparison.Ordinal))
            {
                yield return fullName;
                continue;
            }

            foreach (var prefix in ForbiddenTypeNamespacePrefixes)
            {
                if (fullName.StartsWith(prefix + ".", StringComparison.Ordinal)
                    || string.Equals(fullName, prefix, StringComparison.Ordinal))
                {
                    yield return fullName;
                }
            }
        }
    }

    internal static IEnumerable<string> NonPrivateLoggerFields()
    {
        foreach (var type in ProductionAssembly.GetTypes())
        {
            foreach (var field in type.GetFields(
                         BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (!IsLoggerField(field.FieldType))
                {
                    continue;
                }

                if (field.IsPublic || field.IsStatic)
                {
                    yield return type.FullName + "." + field.Name;
                }
            }
        }
    }

    private static bool IsLoggerField(Type type)
    {
        return type.FullName is "Microsoft.Extensions.Logging.ILogger"
            || (type.IsGenericType
                && type.GetGenericTypeDefinition().FullName is "Microsoft.Extensions.Logging.ILogger`1");
    }

    private static IReadOnlyCollection<string> ReferencedTypeFullNames()
    {
        var location = ProductionAssembly.Location;
        if (string.IsNullOrWhiteSpace(location) || !File.Exists(location))
        {
            return [];
        }

        using var stream = File.OpenRead(location);
        using var pe = new PEReader(stream);
        var reader = pe.GetMetadataReader();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var handle in reader.TypeReferences)
        {
            var typeRef = reader.GetTypeReference(handle);
            var ns = reader.GetString(typeRef.Namespace);
            var name = reader.GetString(typeRef.Name);
            names.Add(string.IsNullOrEmpty(ns) ? name : ns + "." + name);
        }

        return names;
    }
}
