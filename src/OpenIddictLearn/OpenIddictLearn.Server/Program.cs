using Serilog.Events;
using Serilog;
using OpenIddict.Server;
using Serilog.Sinks.SystemConsole.Themes;

public class Program
{
    private static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.File(
                    Path.Combine("logs", $"{DateTime.Now.ToString("yyyy-MM-dd")}/infomation.log"),
                    restrictedToMinimumLevel: LogEventLevel.Information,
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: 1_000_000,
                    rollOnFileSizeLimit: true,
                    shared: true,
                    flushToDiskInterval: TimeSpan.FromSeconds(1))
                .WriteTo.File(
                    Path.Combine("logs", $"{DateTime.Now.ToString("yyyy-MM-dd")}/error.log"),
                    restrictedToMinimumLevel: LogEventLevel.Error,
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: 1_000_000,
                    rollOnFileSizeLimit: true,
                    shared: true,
                    flushToDiskInterval: TimeSpan.FromSeconds(1))
                .WriteTo.Console()
                .CreateLogger();

        try
        {
            Log.Information("Starting web host");
            CreateHostBuilder(args).Build().Run();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Host terminated unexpectedly");
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
       Host.CreateDefaultBuilder(args)
           .UseSerilog()// <-- Add this line
           .ConfigureWebHostDefaults(webBuilder =>
           {
               webBuilder.UseStartup<Startup>();
           });
}