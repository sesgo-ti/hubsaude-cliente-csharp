// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

/// <summary>
/// Fail-fast de <see cref="SigningStrategyFactory.FromPkcs11"/> sem HSM.
/// Assinatura real no token fica em <see cref="Pkcs11SoftHsmTests"/> (SoftHSM2).
/// </summary>
public sealed class Pkcs11SigningStrategyTests
{
    [Fact]
    public void deveRejeitarOpcoesNulas()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPkcs11(null!));
    }

    [Fact]
    public void deveExigirKeyLabelOuKeyId()
    {
        var ex = Assert.Throws<ArgumentException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = "softhsm2.dll",
            Pin = "1234",
        }));
        Assert.Contains("keyLabel", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarSlotETokenLabelJuntos()
    {
        var ex = Assert.Throws<ArgumentException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = "softhsm2.dll",
            Pin = "1234",
            KeyLabel = "k",
            Slot = 0,
            TokenLabel = "t",
        }));
        Assert.Contains("slot OU tokenLabel", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarAlgoritmoJwtInvalidoAntesDeAbrirOModulo()
    {
        var ex = Assert.Throws<SmartTokenException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = "softhsm2.dll",
            Pin = "1234",
            KeyLabel = "k",
            JwtAlgorithm = "HS256",
        }));
        Assert.Contains("PKCS#11", ex.Message, StringComparison.Ordinal);
        Assert.Contains("HS256", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharAoCarregarModuloInexistente()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".dll");
        var ex = Assert.Throws<SmartTokenException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = path,
            Pin = "1234",
            KeyLabel = "k",
        }));
        Assert.Contains("Falha ao carregar o m\u00f3dulo PKCS#11", ex.Message, StringComparison.Ordinal);
        Assert.Contains(path, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveExigirBibliotecaEPin()
    {
        Assert.Throws<ArgumentException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = " ",
            Pin = "1234",
            KeyLabel = "k",
        }));
        Assert.Throws<ArgumentException>(() => SigningStrategyFactory.FromPkcs11(new Pkcs11Options
        {
            Library = "softhsm2.dll",
            Pin = "",
            KeyLabel = "k",
        }));
    }
}
