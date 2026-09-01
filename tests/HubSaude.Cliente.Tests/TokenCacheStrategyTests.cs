// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class TokenCacheStrategyTests
{
    private const string ClientId = "cliente-teste";
    private const string Scope = "system/Patient.rs";
    private const int MarginSeconds = 30;

    [Fact]
    public void deveServirTokenArmazenadoSemJsonCru()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 10);
        cache.Store(Scope, new SmartTokenClient.TokenResponse("tok-1", 3600, "{\"raw\":true}"));

        var cached = cache.CachedResponseIfValid(Scope);
        Assert.NotNull(cached);
        Assert.Equal("tok-1", cached.AccessToken);
        Assert.Null(cached.RawJson);
        Assert.InRange(cached.ExpiresIn, 3500, 3600);
    }

    [Fact]
    public void naoDeveServirTokenDentroDaMargem()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 10);
        cache.Store(Scope, new SmartTokenClient.TokenResponse("tok-quase-expirado", 10, null));
        Assert.Null(cache.CachedResponseIfValid(Scope));
    }

    [Fact]
    public void invalidate_DeveRemoverSomenteOScope()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 10);
        cache.Store(Scope, new SmartTokenClient.TokenResponse("tok-1", 3600, null));
        cache.Store("outro/scope", new SmartTokenClient.TokenResponse("tok-2", 3600, null));
        cache.Invalidate(Scope);
        Assert.Null(cache.CachedResponseIfValid(Scope));
        Assert.NotNull(cache.CachedResponseIfValid("outro/scope"));
    }

    [Fact]
    public void invalidateAll_DeveLimparTudo()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 10);
        cache.Store(Scope, new SmartTokenClient.TokenResponse("tok-1", 3600, null));
        cache.Store("outro/scope", new SmartTokenClient.TokenResponse("tok-2", 3600, null));
        cache.InvalidateAll();
        Assert.Null(cache.CachedResponseIfValid(Scope));
        Assert.Null(cache.CachedResponseIfValid("outro/scope"));
    }

    [Fact]
    public void deveRemoverEntradaExpirada()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 2);
        cache.Store(Scope, new SmartTokenClient.TokenResponse("tok-expirado", 10, null));
        Assert.Null(cache.CachedResponseIfValid(Scope));
        Assert.Equal(0, cache.Size);
    }

    [Fact]
    public void deveLimitarCachePorLru()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 2);
        cache.Store("scope-1", new SmartTokenClient.TokenResponse("tok-1", 3600, null));
        cache.Store("scope-2", new SmartTokenClient.TokenResponse("tok-2", 3600, null));
        cache.CachedResponseIfValid("scope-1");
        cache.Store("scope-3", new SmartTokenClient.TokenResponse("tok-3", 3600, null));

        Assert.Equal(2, cache.Size);
        Assert.NotNull(cache.CachedResponseIfValid("scope-1"));
        Assert.Null(cache.CachedResponseIfValid("scope-2"));
        Assert.NotNull(cache.CachedResponseIfValid("scope-3"));
    }

    [Fact]
    public async Task deveLimitarCacheSobConcorrencia()
    {
        const int capacity = 32;
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, capacity);
        var tasks = Enumerable.Range(0, 8).Select(thread => Task.Run(() =>
        {
            var offset = thread * 100;
            for (var i = 0; i < 100; i++)
            {
                var scope = "scope-" + (offset + i);
                cache.Store(scope, new SmartTokenClient.TokenResponse("tok", 3600, null));
                cache.CachedResponseIfValid(scope);
                if (i % 10 == 0)
                {
                    cache.Invalidate(scope);
                }

                Assert.True(cache.Size <= capacity);
            }
        }));
        await Task.WhenAll(tasks);
        for (var i = 0; i < capacity; i++)
        {
            cache.Store("scope-final-" + i, new SmartTokenClient.TokenResponse("tok", 3600, null));
        }

        Assert.Equal(capacity, cache.Size);
    }

    [Fact]
    public void deveRejeitarCapacidadeInvalida()
    {
        var ex = Assert.Throws<ArgumentException>(() => new TokenCacheStrategy(true, MarginSeconds, ClientId, 0));
        Assert.Contains("maxEntries", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void store_EhNoOpQuandoDesabilitado()
    {
        var cache = new TokenCacheStrategy(false, MarginSeconds, ClientId, 10);
        cache.Store(Scope, new SmartTokenClient.TokenResponse("tok-1", 3600, null));
        Assert.Null(cache.CachedResponseIfValid(Scope));
    }

    [Fact]
    public void lockStriping_DeveSerDeterministico()
    {
        var cache = new TokenCacheStrategy(true, MarginSeconds, ClientId, 10);
        Assert.Same(cache.LockFor(Scope), cache.LockFor(Scope));
        Assert.Equal(TokenCacheStrategy.ScopeLockStripes, 32);
        Assert.Equal(
            TokenCacheStrategy.StripeIndex("system/Patient.rs"),
            TokenCacheStrategy.StripeIndex("system/Patient.rs"));
        Assert.InRange(TokenCacheStrategy.StripeIndex("system/Patient.rs"), 0, 31);
    }
}
