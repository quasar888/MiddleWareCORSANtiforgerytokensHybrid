internal class SymmetricKeyIssuerSecurityTokenProvider
{
    private string issuer;
    private byte[] bytes;

    public SymmetricKeyIssuerSecurityTokenProvider(string issuer, byte[] bytes)
    {
        this.issuer = issuer;
        this.bytes = bytes;
    }
}