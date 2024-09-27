using OpenIddict.Abstractions;
using Quartz;

namespace OpenIddictLearn.Server.Jobs
{
    public class TokenCleanupJob : IJob
    {

        private readonly IOpenIddictTokenManager _tokenManager;

        public TokenCleanupJob(IOpenIddictTokenManager tokenManager)
        {
            _tokenManager = tokenManager;
        }
        public async Task Execute(IJobExecutionContext context)
        {
            await _tokenManager.PruneAsync(DateTimeOffset.UtcNow);
        }
    }

}
