using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;

namespace MauiSecureApp;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
			});

		builder.Services.AddMauiBlazorWebView();

#if DEBUG
		builder.Services.AddBlazorWebViewDeveloperTools();
		builder.Logging.AddDebug();
#endif

        builder.Services.AddAuthorizationCore();

        builder.Services.AddCascadingAuthenticationState();
        // This is our custom provider
        builder.Services.AddScoped<ICustomAuthenticationStateProvider, MauiAuthenticationStateProvider>();
        // Use our custom provider when the app needs an AuthenticationStateProvider
        builder.Services.AddScoped<AuthenticationStateProvider>(s
            => (MauiAuthenticationStateProvider)s.GetRequiredService<ICustomAuthenticationStateProvider>());




        return builder.Build();
	}
}
