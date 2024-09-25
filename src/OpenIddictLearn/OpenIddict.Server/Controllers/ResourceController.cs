using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using OpenIddict.Abstractions;
using OpenIddict.Server.Models;
using OpenIddict.Validation.AspNetCore;
using OpenIddictLearn.Server.Resources;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictLearn.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ResourceController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IStringLocalizer<Resource> _localizer;

        public ResourceController(UserManager<ApplicationUser> userManager, IStringLocalizer<Resource> localizer)
        {
            _userManager = userManager;
            _localizer = localizer;
        }

        [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("message")]
        public async Task<IActionResult> GetMessage()
        {
            var user = await _userManager.FindByIdAsync(User.GetClaim(Claims.Subject));
            if (user is null)
            {
                return Challenge(
                    authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] =
                            "The specified access token is bound to an account that no longer exists."
                    }));
            }

            return Content($"{user.UserName} has been successfully authenticated.{_localizer["hello"]}");
        }
    }
}
