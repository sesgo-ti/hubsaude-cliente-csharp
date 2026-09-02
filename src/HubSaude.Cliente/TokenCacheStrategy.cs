// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace HubSaude.Cliente;

/// <summary>
/// Cache de tokens por scope com lock striping para single-flight de renovação:
/// no máximo uma requisição HTTP em voo por scope e uma janela LRU limitada de tokens.
/// </summary>
/// <remarks>
/// <para>
/// Colaborador interno do <see cref="SmartTokenClient"/>: concentra a política de cache
/// (validade com margem de renovação, invalidação) e a seleção de locks por scope que
/// antes inflavam a complexidade da classe principal. Não faz parte da API pública.
/// </para>
/// <para>
/// Os scopes recebidos por esta classe devem estar <strong>normalizados</strong>
/// (<c>trim</c>; <c>null</c> → string vazia) — responsabilidade do chamador.
/// </para>
/// </remarks>
internal sealed class TokenCacheStrategy
{
    /// <summary>
    /// Quantidade fixa de locks usados no striping. Limita a memória a O(1), independentemente
    /// do número de scopes distintos.
    /// </summary>
    internal const int ScopeLockStripes = 32;

    private readonly bool _enabled;
    private readonly int _marginSeconds;
    private readonly string _clientId;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly LruTokenCache _tokenCache;
    private readonly SemaphoreSlim[] _scopeLocks;

    internal TokenCacheStrategy(
        bool enabled,
        int marginSeconds,
        string clientId,
        int maxEntries,
        TimeProvider? timeProvider = null,
        ILogger? logger = null)
    {
        if (maxEntries <= 0)
        {
            throw new ArgumentException("maxEntries deve ser positivo: " + maxEntries, nameof(maxEntries));
        }

        ArgumentNullException.ThrowIfNull(clientId);
        _enabled = enabled;
        _marginSeconds = marginSeconds;
        _clientId = clientId;
        _time = timeProvider ?? TimeProvider.System;
        _logger = logger ?? NullLogger.Instance;
        _tokenCache = new LruTokenCache(maxEntries);
        _scopeLocks = new SemaphoreSlim[ScopeLockStripes];
        for (var i = 0; i < ScopeLockStripes; i++)
        {
            _scopeLocks[i] = new SemaphoreSlim(1, 1);
        }
    }

    /// <summary>
    /// Retorna token cacheado para o scope, se ainda válido com a margem configurada.
    /// </summary>
    internal SmartTokenClient.TokenResponse? CachedResponseIfValid(string normalizedScope)
    {
        if (!_enabled)
        {
            return null;
        }

        var cached = _tokenCache.Get(normalizedScope);
        if (cached is not null && cached.IsValid(_marginSeconds, _time.GetUtcNow()))
        {
            _logger.LogDebug(
                "Retornando token em cache para clientId={ClientId} scope={Scope}",
                _clientId,
                normalizedScope);
            return FromCache(cached);
        }

        if (cached is not null)
        {
            _tokenCache.Remove(normalizedScope, cached);
        }

        return null;
    }

    /// <summary>
    /// Obtém o lock (striping) para single-flight de renovação do scope informado.
    /// </summary>
    internal SemaphoreSlim LockFor(string normalizedScope)
    {
        return _scopeLocks[StripeIndex(normalizedScope)];
    }

    /// <summary>
    /// Calcula o índice do stripe de lock para o scope normalizado.
    /// </summary>
    internal static int StripeIndex(string normalizedScope)
    {
        unchecked
        {
            var hash = 0;
            foreach (var c in normalizedScope)
            {
                hash = (31 * hash) + c;
            }

            return (int)((uint)hash % ScopeLockStripes);
        }
    }

    internal void Store(string normalizedScope, SmartTokenClient.TokenResponse tokenResponse)
    {
        if (!_enabled)
        {
            return;
        }

        var expiresAt = _time.GetUtcNow().AddSeconds(tokenResponse.ExpiresIn);
        _tokenCache.Put(normalizedScope, new CachedToken(tokenResponse.AccessToken, expiresAt));
        _logger.LogDebug(
            "Token cacheado para clientId={ClientId} scope={Scope} expiresIn={ExpiresIn}s",
            _clientId,
            normalizedScope,
            tokenResponse.ExpiresIn);
    }

    internal void InvalidateAll()
    {
        _tokenCache.Clear();
        _logger.LogInformation("Cache de tokens invalidado para clientId={ClientId}", _clientId);
    }

    internal void Invalidate(string normalizedScope)
    {
        _tokenCache.Remove(normalizedScope);
        _logger.LogInformation(
            "Cache invalidado para clientId={ClientId} scope={Scope}",
            _clientId,
            normalizedScope);
    }

    internal int Size => _tokenCache.Size;

    internal void DisposeLocks()
    {
        foreach (var gate in _scopeLocks)
        {
            gate.Dispose();
        }
    }

    private SmartTokenClient.TokenResponse FromCache(CachedToken cached)
    {
        var remaining = (int)Math.Max(0, (cached.ExpiresAt - _time.GetUtcNow()).TotalSeconds);
        return new SmartTokenClient.TokenResponse(cached.AccessToken, remaining, RawJson: null);
    }

    internal sealed record CachedToken(string AccessToken, DateTimeOffset ExpiresAt)
    {
        internal bool IsValid(int marginSeconds, DateTimeOffset now)
        {
            return now.AddSeconds(marginSeconds) < ExpiresAt;
        }

        public override string ToString()
        {
            return "CachedToken[accessToken=[REDACTED], expiresAt=" + ExpiresAt + "]";
        }
    }

    private sealed class LruTokenCache
    {
        private readonly int _capacity;
        private readonly LinkedList<string> _order = new();
        private readonly Dictionary<string, (CachedToken Token, LinkedListNode<string> Node)> _entries;

        internal LruTokenCache(int capacity)
        {
            _capacity = capacity;
            _entries = new Dictionary<string, (CachedToken, LinkedListNode<string>)>(capacity);
        }

        internal CachedToken? Get(string scope)
        {
            lock (_entries)
            {
                if (!_entries.TryGetValue(scope, out var entry))
                {
                    return null;
                }

                _order.Remove(entry.Node);
                _order.AddLast(entry.Node);
                return entry.Token;
            }
        }

        internal void Put(string scope, CachedToken token)
        {
            lock (_entries)
            {
                if (_entries.TryGetValue(scope, out var existing))
                {
                    _order.Remove(existing.Node);
                    var node = _order.AddLast(scope);
                    _entries[scope] = (token, node);
                    return;
                }

                var added = _order.AddLast(scope);
                _entries[scope] = (token, added);
                if (_entries.Count > _capacity)
                {
                    var lru = _order.First!;
                    _order.RemoveFirst();
                    _entries.Remove(lru.Value);
                }
            }
        }

        internal void Remove(string scope, CachedToken token)
        {
            lock (_entries)
            {
                if (_entries.TryGetValue(scope, out var entry) && entry.Token.Equals(token))
                {
                    _order.Remove(entry.Node);
                    _entries.Remove(scope);
                }
            }
        }

        internal void Remove(string scope)
        {
            lock (_entries)
            {
                if (_entries.Remove(scope, out var entry))
                {
                    _order.Remove(entry.Node);
                }
            }
        }

        internal void Clear()
        {
            lock (_entries)
            {
                _entries.Clear();
                _order.Clear();
            }
        }

        internal int Size
        {
            get
            {
                lock (_entries)
                {
                    return _entries.Count;
                }
            }
        }
    }
}
