using System.Security.Claims;
using System.Security.Cryptography;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.Services;

public class OAuthService<TUser> : IOAuthService<TUser>
    where TUser : class, IOAuthUser, new()
{
    private readonly IAccountIdentityStore<TUser> _userStore;
    private readonly IAuthService<TUser> _authService;
    private readonly ILogger<OAuthService<TUser>> _logger;

    public OAuthService(
        IAccountIdentityStore<TUser> userStore,
        IAuthService<TUser> authService,
        ILogger<OAuthService<TUser>> logger)
    {
        _userStore = userStore;
        _authService = authService;
        _logger = logger;
    }

    public async Task<AuthResult<TUser>> HandleOAuthCallbackAsync(
        ExternalLoginInfo loginInfo)
    {
        try
        {
            var email = loginInfo.Principal.FindFirstValue(ClaimTypes.Email);
            var providerId = loginInfo.ProviderKey;
            var provider = loginInfo.LoginProvider.ToLower();

            if (string.IsNullOrEmpty(email))
            {
                return AuthResult<TUser>.Failure("Email not provided by OAuth provider");
            }

            // Check if user exists by provider ID
            var existingUser = await _userStore.FindByProviderAsync(provider, providerId);

            if (existingUser != null)
            {
                return GenerateUserToken(existingUser);
            }

            // Check if user exists by email
            existingUser = await _userStore.FindByEmailAsync(email);

            if (existingUser != null)
            {
                // Link OAuth account to existing user
                existingUser.Provider = provider;
                existingUser.ProviderId = providerId;
                existingUser.IsEmailVerified = true; // OAuth providers verify emails

                if (loginInfo.Principal.HasClaim(c => c.Type == "picture"))
                {
                    existingUser.ProfilePictureUrl =
                        loginInfo.Principal.FindFirstValue("picture");
                }

                await _userStore.SaveAsync(existingUser);

                return GenerateUserToken(existingUser);
            }

            // Create new user
            var newUser = new TUser
            {
                Id = Guid.NewGuid().ToString(),
                Email = email,
                Provider = provider,
                ProviderId = providerId,
                IsEmailVerified = true,
                Name = loginInfo.Principal.FindFirstValue(ClaimTypes.Name) ?? email.Substring(0, email.IndexOf('@')),
                Picture = loginInfo.Principal.FindFirstValue("picture") ?? string.Empty,
                ProfilePictureUrl = loginInfo.Principal.FindFirstValue("picture") ?? string.Empty,
                Roles = ["user"],
                Permissions = ["read"]
            };

            if (loginInfo.Principal.HasClaim(c => c.Type == "picture"))
            {
                newUser.ProfilePictureUrl =
                    loginInfo.Principal.FindFirstValue("picture");
            }

            await _userStore.SaveAsync(newUser);

            return GenerateUserToken(newUser);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling OAuth callback");
            return AuthResult<TUser>.Failure("OAuth authentication failed");
        }
    }


    private AuthResult<TUser> GenerateUserToken(TUser existingUser)
    {
        var user = _authService.GenerateAuthToken(existingUser) ?? throw new Exception("Failed to generate auth token");
        if (!user.IsSuccessful)
        {
            return AuthResult<TUser>.Failure("Failed to generate auth token");
        }

        if (user.User == null)
        {
            return AuthResult<TUser>.Failure("User not found after token generation");
        }
        return AuthResult<TUser>.Success(user.User, user.Token!);
    }



    public async Task<string> GenerateOAuthStateAsync(string provider)
    {
        // Generate secure state token to prevent CSRF
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        // Store state with expiration (implement in token store)
        return state;
    }

    public async Task<bool> ValidateOAuthStateAsync(string state)
    {
        // Validate and consume state token
        // Implement in token store
        return true;
    }
}
