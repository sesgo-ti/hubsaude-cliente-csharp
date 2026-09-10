// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace HubSaude.Cliente.Tests;

/// <summary>
/// Assinatura PKCS#11 de ponta a ponta contra SoftHSM2. Sem o módulo ou o
/// <c>softhsm2-util</c>, os casos retornam imediatamente (a suíte unitária
/// permanece independente de HSM). No CI Linux o workflow instala SoftHSM2.
/// </summary>
/// <remarks>
/// O par RSA é gerado no token via <c>C_GenerateKeyPair</c> (mesmo fluxo do
/// cliente TypeScript), não importado de PEM — importação via
/// <c>softhsm2-util --import</c> falha ou produz chaves incompatíveis com
/// <c>CKM_SHA384_RSA_PKCS</c> em alguns builds do SoftHSM2 no Ubuntu.
/// </remarks>
public sealed class Pkcs11SoftHsmTests : IClassFixture<SoftHsmFixture>
{
    private readonly SoftHsmFixture _fx;

    public Pkcs11SoftHsmTests(SoftHsmFixture fixture)
    {
        _fx = fixture;
    }

    [Fact]
    public void deveAssinarRs384NoTokenEVerificarComAChavePublica()
    {
        if (!_fx.EnsureAvailable())
        {
            return;
        }

        using var strategy = (Pkcs11SigningStrategy)SigningStrategyFactory.FromPkcs11(_fx.Options());
        var data = Encoding.UTF8.GetBytes("client-assertion");
        var signature = strategy.Sign(data);
        Assert.NotEmpty(signature);
        Assert.True(_fx.PublicRsa!.VerifyData(
            data, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));

        strategy.Dispose();
        Assert.Throws<ObjectDisposedException>(() => strategy.Sign(data));
    }

    [Fact]
    public void deveFalharComChaveInexistenteNoToken()
    {
        if (!_fx.EnsureAvailable())
        {
            return;
        }

        var options = _fx.Options();
        var ex = Assert.Throws<SmartTokenException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = options.Library,
            Pin = options.Pin,
            TokenLabel = options.TokenLabel,
            KeyLabel = "nao-existe",
        }));
        Assert.Contains("Nenhuma chave privada", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveVerificarConsistenciaComCertificadoDaMesmaChave()
    {
        if (!_fx.EnsureAvailable())
        {
            return;
        }

        using var strategy = (Pkcs11SigningStrategy)SigningStrategyFactory.FromPkcs11(_fx.Options());
        using var cert = CryptoFixtures.SelfSignedCert(_fx.PublicRsa!);
        KeyCertificateConsistency.VerifyStrategy(strategy, cert);
    }
}

/// <summary>
/// Token SoftHSM2 temporário compartilhado pelos testes PKCS#11.
/// </summary>
public sealed class SoftHsmFixture : IDisposable
{
    internal const string Pin = "123456";
    private const string SoPin = "0000";

    internal string? Library { get; }
    internal RSA? PublicRsa { get; private set; }
    internal string Label { get; } = "hubsaude-it-" + Guid.NewGuid().ToString("N")[..8];
    internal string KeyLabel { get; } = "jwt-key";

    private readonly string? _tokensDir;
    private readonly string? _conf;

    public SoftHsmFixture()
    {
        Library = ResolveLibrary();
        if (Library is null || !HasUtil())
        {
            if (IsCi)
            {
                throw new InvalidOperationException(
                    "CI exige SoftHSM2 (softhsm2-util e SOFTHSM_LIB / libsofthsm2.so).");
            }

            return;
        }

        _tokensDir = Directory.CreateTempSubdirectory("softhsm-").FullName;
        _conf = Path.Combine(_tokensDir, "softhsm2.conf");
        File.WriteAllText(_conf, "directories.tokendir = " + _tokensDir.Replace('\\', '/') + Environment.NewLine
            + "objectstore.backend = file" + Environment.NewLine
            + "log.level = ERROR" + Environment.NewLine);
        Environment.SetEnvironmentVariable("SOFTHSM2_CONF", _conf);

        RunUtil("--init-token", "--free", "--label", Label, "--so-pin", SoPin, "--pin", Pin);
        GenerateRsaKeyPairOnToken();
    }

    internal bool EnsureAvailable()
    {
        return Library is not null && PublicRsa is not null;
    }

    internal Pkcs11Options Options()
    {
        return new Pkcs11Options
        {
            Library = Library!,
            Pin = Pin,
            TokenLabel = Label,
            KeyLabel = KeyLabel,
            JwtAlgorithm = "RS384",
        };
    }

    public void Dispose()
    {
        PublicRsa?.Dispose();
        if (_tokensDir is not null)
        {
            try
            {
                Directory.Delete(_tokensDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    private void GenerateRsaKeyPairOnToken()
    {
        Pkcs11SigningStrategy.EnsureNativeLibraryResolver();
        var factories = new Pkcs11InteropFactories();
        using var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, Library!, AppType.MultiThreaded);
        var slot = lib.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => string.Equals(s.GetTokenInfo().Label.Trim(), Label, StringComparison.Ordinal));
        using var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, Pin);

        var pub = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 1, 0, 1 }),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, KeyLabel),
        };
        var priv = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, KeyLabel),
        };
        var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        session.GenerateKeyPair(mechanism, pub, priv, out var publicKey, out _);

        var modulus = session.GetAttributeValue(publicKey, [CKA.CKA_MODULUS])[0].GetValueAsByteArray();
        var exponent = session.GetAttributeValue(publicKey, [CKA.CKA_PUBLIC_EXPONENT])[0].GetValueAsByteArray();
        PublicRsa = RSA.Create();
        PublicRsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
    }

    private void RunUtil(params string[] args)
    {
        var psi = new ProcessStartInfo("softhsm2-util")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.Environment["SOFTHSM2_CONF"] = _conf!;
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(
            process.ExitCode == 0,
            "softhsm2-util " + string.Join(' ', args) + " falhou (" + process.ExitCode + "): "
            + stderr + stdout);
    }

    private static bool HasUtil()
    {
        try
        {
            var psi = new ProcessStartInfo("softhsm2-util")
            {
                Arguments = "--help",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            process?.WaitForExit(TimeSpan.FromSeconds(5));
            return process is { ExitCode: 0 or 1 };
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string? ResolveLibrary()
    {
        var fromEnv = Environment.GetEnvironmentVariable("SOFTHSM_LIB");
        if (!string.IsNullOrWhiteSpace(fromEnv) && File.Exists(fromEnv))
        {
            return fromEnv;
        }

        string[] candidates =
        [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "SoftHSM2",
                "lib",
                "softhsm2-x64.dll"),
        ];
        return Array.Find(candidates, File.Exists);
    }

    private static bool IsCi =>
        string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);
}
