using Microsoft.AspNetCore.Mvc;
using RealCreate.Web.MiddleWare;

namespace RealCreate.Web.Controllers
{
    public class HomeController : Controller
    {
        [ServiceFilter(typeof(CustomActionFilter))]
        public IActionResult Index()
        {
            return View();
        }
    }
}
