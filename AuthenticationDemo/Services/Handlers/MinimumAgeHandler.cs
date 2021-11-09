using AuthenticationDemo.Services.Requirements;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AuthenticationDemo.Services.Handlers
{
    public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                       MinimumAgeRequirement requirement)
        {
            var dateOfBirthClaim = context.User.Claims.FirstOrDefault(a => a.Type == ClaimTypes.DateOfBirth);
            if (dateOfBirthClaim == null) 
            {
                return Task.CompletedTask;
            }

            var dateOfBirth = Convert.ToDateTime(dateOfBirthClaim.Value);

            int calculatedAge = DateTime.Today.Year - dateOfBirth.Year;
            if (dateOfBirth > DateTime.Today.AddYears(-calculatedAge))
            {
                calculatedAge--;
            }

            if (calculatedAge >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}
