using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

/// <summary>
/// Interface for storing OAuth state tokens
/// </summary>
public interface IOAuthStateStore
{
  Task StoreStateAsync(OAuthState state);
  Task<OAuthState?> GetStateAsync(string token);
  Task UpdateStateAsync(OAuthState state);
  Task DeleteStateAsync(string token);
  Task CleanupExpiredStatesAsync();
}