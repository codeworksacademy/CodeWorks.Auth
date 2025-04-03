namespace CWAuth.Interfaces;

public interface IAccountIdentityTokenStore
{
    Task SaveTokenAsync(TokenRecord token);
    Task<TokenRecord?> GetValidTokenAsync(string token, EmailTokenPurpose purpose);
    Task MarkTokenUsedAsync(string token);
}
