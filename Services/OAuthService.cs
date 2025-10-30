using System.Security.Claims;
using Microsoft.Extensions.Logging;
using CodeWorks.Auth.Interfaces;
using Microsoft.AspNetCore.Identity;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class OAuthService<TIdentity> : IOAuthService<TIdentity> where TIdentity : class, IAccountIdentity, new()
{
    private readonly IAccountIdentityStore<TIdentity> _userStore;
    private readonly IAuthService<TIdentity> _authService;
    private readonly IOAuthStateStore _oauthStateStore;
    private readonly ILogger<OAuthService<TIdentity>> _logger;

    public OAuthService(
        IAccountIdentityStore<TIdentity> userStore,
        IAuthService<TIdentity> authService,
        IOAuthStateStore oauthStateStore,
        ILogger<OAuthService<TIdentity>> logger)
    {
        _userStore = userStore;
        _authService = authService;
        _oauthStateStore = oauthStateStore;
        _logger = logger;
    }

    public Task<string> GenerateOAuthStateAsync(string provider, string? returnUrl = null)
    {
        var stateToken = Guid.NewGuid().ToString("N");
        var state = new OAuthState
        {
            Token = stateToken,
            Provider = provider,
            ReturnUrl = returnUrl,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10)
        };

        return _oauthStateStore.StoreStateAsync(state)
          .ContinueWith(_ => stateToken);
    }

    public async Task<AuthResult<TIdentity>> HandleOAuthCallbackAsync(ExternalLoginInfo loginInfo)
    {
        try
        {

            var email = loginInfo.Principal.FindFirstValue(ClaimTypes.Email);
            var name = loginInfo.Principal.FindFirstValue(ClaimTypes.Name)
                       ?? loginInfo.Principal.FindFirstValue("name")
                       ?? loginInfo.Principal.FindFirstValue("given_name")
                       ?? loginInfo.Principal.FindFirstValue("preferred_username")
                       ?? email?.Split('@')[0]
                       ?? "User";
            var providerId = loginInfo.ProviderKey;
            var provider = loginInfo.LoginProvider.ToLower();
            var picture = loginInfo.Principal.FindFirstValue("picture")
                       ?? loginInfo.Principal.FindFirstValue("urn:facebook:picture")
                       ?? loginInfo.Principal.FindFirstValue("avatar_url")
                       ?? loginInfo.Principal.FindFirstValue("profile_image_url")
                       ?? loginInfo.Principal.FindFirstValue("icon_url")
                       ?? loginInfo.Principal.FindFirstValue("photo")
                       ?? loginInfo.Principal.FindFirstValue("picture_url")
                       ?? loginInfo.Principal.FindFirstValue("profile_image")
                       ?? loginInfo.Principal.FindFirstValue("image")
                       ?? loginInfo.Principal.FindFirstValue("profile_photo_url")
                       ?? loginInfo.Principal.FindFirstValue("user_image")
                       ?? loginInfo.Principal.FindFirstValue("user_photo_url")
                       ?? loginInfo.Principal.FindFirstValue("avatar")
                       ?? loginInfo.Principal.FindFirstValue("profilePic")
                       ?? loginInfo.Principal.FindFirstValue("profile_picture")
                       ?? "";


            if (string.IsNullOrEmpty(email))
            {
                _logger.LogWarning("OAuth provider {Provider} did not return email", provider);
                return AuthResult<TIdentity>.Failure("Email not provided by OAuth provider.");
            }

            // Normalize email
            email = email.Trim().ToLowerInvariant();

            // Check if user exists by provider ID
            var existingUser = await _userStore.FindByProviderAsync(provider, providerId);

            if (existingUser != null)
            {
                _logger.LogInformation("Existing OAuth user logged in: {Email}", existingUser.Email);
                var token = _authService.GenerateAuthToken(existingUser);
                return AuthResult<TIdentity>.Success(existingUser, token.Token!);
            }

            // Check if user exists by email (link OAuth to existing account)
            existingUser = await _userStore.FindByEmailAsync(email);

            if (existingUser != null)
            {
                _logger.LogInformation("Linking OAuth account to existing user: {Email}", email);

                // Link OAuth provider to existing account
                existingUser.Provider = provider;
                existingUser.ProviderId = providerId;
                existingUser.IsEmailVerified = true; // OAuth providers verify emails
                existingUser.Name ??=
                existingUser.Email = email;
                existingUser.Roles ??= new List<string> { "User" };
                existingUser.Permissions ??= new List<string>();
                existingUser.Picture ??= picture;
                existingUser.ProfilePictureUrl ??= picture;
                existingUser.LastLoginAt = DateTime.UtcNow;


                if (!string.IsNullOrEmpty(picture))
                {
                    existingUser.ProfilePictureUrl = picture;
                }

                await _userStore.SaveAsync(existingUser);

                var token = _authService.GenerateAuthToken(existingUser);
                return AuthResult<TIdentity>.Success(existingUser, token.Token!);
            }

            // Create new user from OAuth
            _logger.LogInformation("Creating new user from OAuth: {Email}", email);

            TIdentity newUserCreation = new()
            {
                Id = Guid.NewGuid().ToString(),
                Email = email,
                Name = name,
                Provider = provider,
                ProviderId = providerId,
                IsEmailVerified = true, // OAuth providers verify emails
                ProfilePictureUrl = picture,
                Picture = picture,
                Roles = ["User"],
                Permissions = [],
                LastLoginAt = DateTime.UtcNow,
                PasswordHash = string.Empty // OAuth users don't have passwords
            };

            await _userStore.CreateAsync(newUserCreation);
            var newUser = await _userStore.FindByProviderAsync(provider, providerId);


            var newToken = _authService.GenerateAuthToken(newUser);
            return AuthResult<TIdentity>.Success(newUser, newToken.Token!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling OAuth callback for provider {Provider}",
                loginInfo.LoginProvider);
            return AuthResult<TIdentity>.Failure("OAuth authentication failed. Please try again.");
        }
    }

    public Task<bool> ValidateOAuthStateAsync(string state)
    {
        return _oauthStateStore.GetStateAsync(state)
            .ContinueWith(task =>
            {
                var oauthState = task.Result;
                if (oauthState == null || oauthState.ExpiresAt < DateTime.UtcNow)
                {
                    return false;
                }
                return true;
            });
    }
}
