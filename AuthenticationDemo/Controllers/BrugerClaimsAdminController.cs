using System.Text;
using AuthenticationDemo.Models;
using AuthenticationDemo.Services.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationDemo.Controllers;

public class BrugerClaimsAdminController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public BrugerClaimsAdminController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }


    // GET: BrugerAdminController
    public ActionResult Index()
    {
        var cp = User.Identities.First();
        return View(cp.Claims.ToList());
    }


    // GET: BrugerAdminController/Create
    public ActionResult Create()
    {
        return View();
    }

    // POST: BrugerAdminController/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Create(ClaimViewModel claimViewModel)
    {
        if (ModelState.IsValid)
        {
            var result = await User.AddOrUpdateClaimAsync(_userManager, _signInManager, claimViewModel.Type,
                claimViewModel.Value);
            if (result == IdentityResult.Failed())
            {
                var sb = new StringBuilder();
                result.Errors.ToList().ForEach(a => sb.AppendLine(a.Description));
                throw new Exception(sb.ToString());
            }

            return RedirectToAction(nameof(Index));
        }

        return View(claimViewModel);
    }

    // GET: BrugerAdminController/Edit/5
    public ActionResult Edit(string id)
    {
        var claimType = id.Replace("%2F", "/");
        var cp = User.Identities.First();
        var claim = cp.Claims.FirstOrDefault(a => a.Type == claimType);
        if (claim == null) return RedirectToAction(nameof(Index));

        return View(new ClaimViewModel {Type = claim.Type, Value = claim.Value});
    }

    // POST: BrugerAdminController/Edit/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Edit(ClaimViewModel claimViewModel)
    {
        if (ModelState.IsValid)
        {
            var result = await User.AddOrUpdateClaimAsync(_userManager, _signInManager, claimViewModel.Type,
                claimViewModel.Value);
            if (result == IdentityResult.Failed())
            {
                var sb = new StringBuilder();
                result.Errors.ToList().ForEach(a => sb.AppendLine(a.Description));
                throw new Exception(sb.ToString());
            }

            return RedirectToAction(nameof(Index));
        }

        return View(claimViewModel);
    }

    // GET: BrugerAdminController/Delete/5
    public ActionResult Delete(string id)
    {
        var claimType = id.Replace("%2F", "/");
        var cp = User.Identities.First();
        var claim = cp.Claims.FirstOrDefault(a => a.Type == claimType);
        if (claim == null) return RedirectToAction(nameof(Index));

        return View(new ClaimViewModel {Type = claim.Type, Value = claim.Value});
    }

    // POST: BrugerAdminController/Delete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Delete(ClaimViewModel claimViewModel)
    {
        var result = await User.DeleteClaimAsync(_userManager, _signInManager, claimViewModel.Type);
        if (result == IdentityResult.Failed())
        {
            var sb = new StringBuilder();
            result.Errors.ToList().ForEach(a => sb.AppendLine(a.Description));
            throw new Exception(sb.ToString());
        }

        return RedirectToAction(nameof(Index));
    }
}