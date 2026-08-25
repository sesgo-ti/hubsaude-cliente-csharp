namespace HubSaude.Cliente.Tests;

public sealed class AssemblySmokeTests
{
    [Fact]
    public void BibliotecaReferenciada_DeveCarregar()
    {
        var assembly = typeof(HubSaude.Cliente.AssemblyMarker).Assembly;
        Assert.Equal("HubSaude.Cliente", assembly.GetName().Name);
    }
}
