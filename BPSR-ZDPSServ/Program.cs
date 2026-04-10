using BPSR_DeepsServ.Models;
using Microsoft.AspNetCore.Mvc;


namespace BPSR_DeepsServ
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateSlimBuilder(args);

            builder.Configuration
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            builder.Services.Configure<Settings>(builder.Configuration.GetSection("ZDPS"));
            builder.Services.AddSingleton<DedupeManager>();
            builder.Services.AddSingleton<DiscordWebHookManager>();

            builder.Services.ConfigureHttpJsonOptions(options =>
            {
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
            });

            var app = builder.Build();

            var zdpsSetings = builder.Configuration.GetSection("ZDPS").Get<Settings>() ?? new Settings();
            if (zdpsSetings?.EnableDiscordWebhookProxy ?? false)
            {
                var reportsAPI = app.MapGroup("/report");
                reportsAPI.MapPost("/discord/{id}/{token}", HandleDiscordReport).DisableAntiforgery();
            }

            if (zdpsSetings?.EnableReportDeduplicationAPI ?? false)
            {
                app.MapGet("/dedupecheck/{teamId}", HandleDedupeRequest).DisableAntiforgery();
            }

            if (zdpsSetings?.EnableChatForwarding ?? false)
            {
                app.MapPost("/chat", HandleChatMessage).DisableAntiforgery();
            }

            if (zdpsSetings?.EnableNotificationForwarding ?? false)
            {
                app.MapPost("/notification", HandleNotification).DisableAntiforgery();
            }

            app.Run();
        }

        private static async Task<IResult> HandleDedupeRequest([FromRoute] ulong teamId, DedupeManager dedupeManager)
        {
            var isDupe = dedupeManager.IsDupe(teamId);
            return Results.Ok(new DedupeResp() { CanSend = !isDupe });
        }

        static async Task<IResult> HandleNotification([FromBody] NotificationRequest notification, DiscordWebHookManager discordWebHooks)
        {
            try
            {
                await discordWebHooks.ForwardNotification(notification);
                return Results.Ok();
            }
            catch (Exception)
            {
                return Results.InternalServerError();
            }
        }

        static async Task<IResult> HandleChatMessage([FromBody] ChatMessageRequest chatMessage, DiscordWebHookManager discordWebHooks)
        {
            try
            {
                await discordWebHooks.ForwardChatMessage(chatMessage);
                return Results.Ok();
            }
            catch (Exception)
            {
                return Results.InternalServerError();
            }
        }

        static async Task<IResult> HandleDiscordReport([FromRoute] string id, [FromRoute] string token, [FromForm] string payload_json, [FromForm] IFormFileCollection files, HttpRequest request, DiscordWebHookManager discordWebHooks)
        {
            try
            {
                if (request.Headers.TryGetValue("X-ZDPS-TeamId", out var teamIdStr))
                {
                    if (ulong.TryParse(teamIdStr, out var teamId))
                    {
                        var result = await discordWebHooks.ProcessEncounterReport(id, token, teamId, payload_json, files);
                        return result.IsSuccessStatusCode ? Results.Ok(result) : Results.BadRequest(result);
                    }
                    else
                    {
                        return Results.Ok("Nope");
                    }
                }
                else
                {
                    return Results.Ok("Nope");
                }
            }
            catch (Exception ex)
            {
                return Results.InternalServerError();
            }
        }
    }
}
