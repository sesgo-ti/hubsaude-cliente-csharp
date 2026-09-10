// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace HubSaude.Cliente;

/// <summary>
/// <see cref="ISigningStrategy"/> que delega a assinatura a um HSM/token PKCS#11.
/// A chave privada não é extraída do hardware.
/// </summary>
public sealed class Pkcs11SigningStrategy : ISigningStrategy, IDisposable
{
    private const int PssSaltLen256 = 32;
    private const int PssSaltLen384 = 48;
    private const int PssSaltLen512 = 64;

    private static readonly ConcurrentDictionary<string, Lazy<IPkcs11Library>> Libraries =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ISession _session;
    private readonly IObjectHandle _privateKey;
    private readonly CKM _mechanism;
    private readonly PssSpec? _pss;
    private readonly HashAlgorithmName? _preHash;
    private readonly string _jwtAlgorithm;
    private readonly object _gate = new();
    private bool _disposed;

    private Pkcs11SigningStrategy(
        ISession session,
        IObjectHandle privateKey,
        CKM mechanism,
        PssSpec? pss,
        HashAlgorithmName? preHash,
        string jwtAlgorithm)
    {
        _session = session;
        _privateKey = privateKey;
        _mechanism = mechanism;
        _pss = pss;
        _preHash = preHash;
        _jwtAlgorithm = jwtAlgorithm;
    }

    internal HashAlgorithmName HashAlgorithm =>
        _preHash ?? _pss?.HashName ?? HashFromRsaMechanism(_mechanism);

    internal RSASignaturePadding? RsaPadding => _preHash is not null
        ? null
        : _pss is null ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss;

    internal static Pkcs11SigningStrategy Open(Pkcs11Options options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Library);
        ArgumentException.ThrowIfNullOrEmpty(options.Pin);
        if (options.KeyLabel is null && (options.KeyId is null || options.KeyId.Length == 0))
        {
            throw new ArgumentException("Defina keyLabel e/ou keyId para localizar a chave privada PKCS#11");
        }

        if (options.Slot is not null && options.TokenLabel is not null)
        {
            throw new ArgumentException("Defina slot OU tokenLabel para localizar o token PKCS#11, n\u00e3o ambos");
        }

        var jwtAlgorithm = string.IsNullOrWhiteSpace(options.JwtAlgorithm)
            ? SmartTokenClient.DefaultJwtAlgorithm
            : options.JwtAlgorithm;
        var (mechanism, pss, preHash) = MapJwtAlgorithm(jwtAlgorithm);

        IPkcs11Library library;
        try
        {
            library = GetOrLoadLibrary(options.Library);
        }
        catch (Exception ex) when (ex is not SmartTokenException)
        {
            throw new SmartTokenException("Falha ao carregar o m\u00f3dulo PKCS#11: " + options.Library, ex);
        }

        var slot = FindSlot(library, options);
        var session = slot.OpenSession(SessionType.ReadOnly);
        try
        {
            Login(session, options.Pin, options.Library);
            var privateKey = FindPrivateKey(session, options);
            return new Pkcs11SigningStrategy(session, privateKey, mechanism, pss, preHash, jwtAlgorithm);
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var payload = _preHash is { } hash ? HashData(data, hash) : data;
        lock (_gate)
        {
            try
            {
                var mech = CreateMechanism();
                return _session.Sign(mech, _privateKey, payload);
            }
            catch (Exception ex) when (ex is not SigningException and not ObjectDisposedException)
            {
                throw new SigningException(
                    "Falha ao assinar dados via PKCS#11 (mecanismo " + _jwtAlgorithm + ")", ex);
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            _session.Dispose();
        }
        catch (Exception)
        {
            // Encerramento idempotente: n\u00e3o impede o restante do Dispose do cliente.
        }
    }

    private IMechanism CreateMechanism()
    {
        if (_pss is null)
        {
            return _session.Factories.MechanismFactory.Create(_mechanism);
        }

        var pssParams = _session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
            _pss.HashAlg,
            _pss.Mgf,
            _pss.SaltLen);
        return _session.Factories.MechanismFactory.Create(_mechanism, pssParams);
    }

    private static IPkcs11Library GetOrLoadLibrary(string path)
    {
        return Libraries.GetOrAdd(
            path,
            static p => new Lazy<IPkcs11Library>(() => LoadLibrary(p))).Value;
    }

    private static IPkcs11Library LoadLibrary(string path)
    {
        var factories = new Pkcs11InteropFactories();
        return factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            factories,
            path,
            AppType.MultiThreaded);
    }

    private static ISlot FindSlot(IPkcs11Library library, Pkcs11Options options)
    {
        var slots = library.GetSlotList(SlotsType.WithTokenPresent);
        if (slots.Count == 0)
        {
            throw new SmartTokenException(
                "Nenhum slot com token presente encontrado em " + options.Library);
        }

        if (options.Slot is { } index)
        {
            if (index < 0 || index >= slots.Count)
            {
                throw new SmartTokenException(
                    "Slot " + index + " n\u00e3o existe (" + slots.Count
                    + " slot(s) com token dispon\u00edvel)");
            }

            return slots[index];
        }

        if (options.TokenLabel is not null)
        {
            foreach (var slot in slots)
            {
                if (string.Equals(slot.GetTokenInfo().Label.Trim(), options.TokenLabel, StringComparison.Ordinal))
                {
                    return slot;
                }
            }

            throw new SmartTokenException(
                "Nenhum token com label '" + options.TokenLabel + "' encontrado");
        }

        return slots[0];
    }

    private static void Login(ISession session, string pin, string library)
    {
        try
        {
            session.Login(CKU.CKU_USER, pin);
        }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
            // Login \u00e9 propriedade do token, n\u00e3o da sess\u00e3o.
        }
        catch (Exception ex) when (ex is not SmartTokenException)
        {
            throw new SmartTokenException(
                "Falha ao autenticar no token PKCS#11 (PIN incorreto?): " + library, ex);
        }
    }

    private static IObjectHandle FindPrivateKey(ISession session, Pkcs11Options options)
    {
        var template = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
        };
        if (options.KeyLabel is not null)
        {
            template.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, options.KeyLabel));
        }

        if (options.KeyId is { Length: > 0 })
        {
            template.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, options.KeyId));
        }

        var found = session.FindAllObjects(template);
        if (found.Count == 0)
        {
            var description = new List<string>();
            if (options.KeyLabel is not null)
            {
                description.Add("label '" + options.KeyLabel + "'");
            }

            if (options.KeyId is { Length: > 0 })
            {
                description.Add("id '" + Convert.ToHexString(options.KeyId) + "'");
            }

            throw new SmartTokenException(
                "Nenhuma chave privada com " + string.Join(" e ", description) + " encontrada no token");
        }

        return found[0];
    }

    private static (CKM Mechanism, PssSpec? Pss, HashAlgorithmName? PreHash) MapJwtAlgorithm(string jwtAlgorithm)
    {
        return jwtAlgorithm.ToUpperInvariant() switch
        {
            "RS256" => (CKM.CKM_SHA256_RSA_PKCS, null, null),
            "RS384" => (CKM.CKM_SHA384_RSA_PKCS, null, null),
            "RS512" => (CKM.CKM_SHA512_RSA_PKCS, null, null),
            "PS256" => (
                CKM.CKM_SHA256_RSA_PKCS_PSS,
                new PssSpec(
                    Convert.ToUInt64(CKM.CKM_SHA256),
                    Convert.ToUInt64(CKG.CKG_MGF1_SHA256),
                    PssSaltLen256,
                    HashAlgorithmName.SHA256),
                null),
            "PS384" => (
                CKM.CKM_SHA384_RSA_PKCS_PSS,
                new PssSpec(
                    Convert.ToUInt64(CKM.CKM_SHA384),
                    Convert.ToUInt64(CKG.CKG_MGF1_SHA384),
                    PssSaltLen384,
                    HashAlgorithmName.SHA384),
                null),
            "PS512" => (
                CKM.CKM_SHA512_RSA_PKCS_PSS,
                new PssSpec(
                    Convert.ToUInt64(CKM.CKM_SHA512),
                    Convert.ToUInt64(CKG.CKG_MGF1_SHA512),
                    PssSaltLen512,
                    HashAlgorithmName.SHA512),
                null),
            "ES256" => (CKM.CKM_ECDSA, null, HashAlgorithmName.SHA256),
            "ES384" => (CKM.CKM_ECDSA, null, HashAlgorithmName.SHA384),
            "ES512" => (CKM.CKM_ECDSA, null, HashAlgorithmName.SHA512),
            _ => throw new SmartTokenException(
                "Algoritmo JWT n\u00e3o suportado para PKCS#11: " + jwtAlgorithm
                + ". Algoritmos v\u00e1lidos: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512"),
        };
    }

    private static HashAlgorithmName HashFromRsaMechanism(CKM mechanism)
    {
        return mechanism switch
        {
            CKM.CKM_SHA512_RSA_PKCS or CKM.CKM_SHA512_RSA_PKCS_PSS => HashAlgorithmName.SHA512,
            CKM.CKM_SHA256_RSA_PKCS or CKM.CKM_SHA256_RSA_PKCS_PSS => HashAlgorithmName.SHA256,
            _ => HashAlgorithmName.SHA384,
        };
    }

    private static byte[] HashData(byte[] data, HashAlgorithmName hash)
    {
        if (hash == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }

        if (hash == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(data);
        }

        return SHA384.HashData(data);
    }

    private sealed record PssSpec(ulong HashAlg, ulong Mgf, ulong SaltLen, HashAlgorithmName HashName);
}
