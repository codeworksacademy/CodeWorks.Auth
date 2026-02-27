using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace CodeWorks.Auth.MvcSample;

public class Program
{

    public static long Port => 5055;

    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
                webBuilder.UseUrls($"http://localhost:{Port}");
            });
}
