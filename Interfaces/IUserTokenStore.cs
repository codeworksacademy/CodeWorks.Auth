namespace CodeWorks.Auth.Interfaces;

public interface IUserTokenStore
{
    Task SaveTokenAsync(TokenRecord token);
    Task<TokenRecord?> GetValidTokenAsync(string token, EmailTokenPurpose purpose);
    Task MarkTokenUsedAsync(string token);
}
