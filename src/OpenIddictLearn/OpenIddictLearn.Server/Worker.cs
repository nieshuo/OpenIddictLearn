using OpenIddict.Abstractions;
using OpenIddict.Server.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Globalization;

namespace OpenIddictLearn.Server
{
    public class Worker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public Worker(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            await RegisterApplicationsAsync(scope.ServiceProvider);
            await RegisterScopesAsync(scope.ServiceProvider);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public static async Task RegisterApplicationsAsync(IServiceProvider provider)
        {
            var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("console_app") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "console_app",
                    ClientType = ClientTypes.Public,
                    RedirectUris =
                {
                    new Uri("http://localhost/")
                },
                    Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "api1",
                    Permissions.Prefixes.Scope + "api2"
                }
                });
            }

            if (await manager.FindByClientIdAsync("spa") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "spa",
                    ClientType = ClientTypes.Public,
                    RedirectUris =
                {
                    new Uri("http://localhost:5112/index.html"),
                    new Uri("http://localhost:5112/signin-callback.html"),
                    new Uri("http://localhost:5112/signin-silent-callback.html"),
                },
                    Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "api1",
                    Permissions.Prefixes.Scope + "api2"
                },
                    Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange,
                },
                });
            }

            if (await manager.FindByClientIdAsync("resource_server_1") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "resource_server_1",
                    ClientSecret = "846B62D0-DEF9-4215-A99D-86E6B8DAB342",
                    Permissions =
                {
                    Permissions.Endpoints.Introspection
                }
                });
            }

            // Angular UI client
            if (await manager.FindByClientIdAsync("angularclient") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "angularclient",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "angular client PKCE",
                    DisplayNames =
                        {
                            [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente MVC"
                        },
                    PostLogoutRedirectUris =
                        {
                            new Uri("https://localhost:4200")
                        },
                    RedirectUris =
                        {
                            new Uri("https://localhost:4200")
                        },
                    Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Logout,
                            Permissions.Endpoints.Token,
                            Permissions.Endpoints.Revocation,
                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.GrantTypes.RefreshToken,
                            Permissions.ResponseTypes.Code,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Roles,
                            Permissions.Prefixes.Scope + "dataEventRecords"
                        },
                    Requirements =
                        {
                            Requirements.Features.ProofKeyForCodeExchange
                        }
                });
            }

            // API application CC
            if (await manager.FindByClientIdAsync("CC") == null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "CC",
                    ClientSecret = "cc_secret",
                    DisplayName = "CC for protected API",
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.Prefixes.Scope + "dataEventRecords"
                    }
                });
            }

            // API
            if (await manager.FindByClientIdAsync("rs_dataEventRecordsApi") == null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = "rs_dataEventRecordsApi",
                    ClientSecret = "dataEventRecordsSecret",
                    Permissions =
                        {
                            Permissions.Endpoints.Introspection
                        }
                };

                await manager.CreateAsync(descriptor);
            }

            // Blazor Hosted
            if (await manager.FindByClientIdAsync("blazorcodeflowpkceclient") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "blazorcodeflowpkceclient",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "Blazor code PKCE",
                    DisplayNames =
                        {
                            [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente MVC"
                        },
                    PostLogoutRedirectUris =
                        {
                            new Uri("https://localhost:44348/signout-callback-oidc"),
                            new Uri("https://localhost:5001/signout-callback-oidc")
                        },
                    RedirectUris =
                        {
                            new Uri("https://localhost:44348/signin-oidc"),
                            new Uri("https://localhost:5001/signin-oidc")
                        },
                    ClientSecret = "codeflow_pkce_client_secret",
                    Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Logout,
                            Permissions.Endpoints.Token,
                            Permissions.Endpoints.Revocation,
                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.GrantTypes.RefreshToken,
                            Permissions.ResponseTypes.Code,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Roles,
                            Permissions.Prefixes.Scope + "dataEventRecords"
                        },
                    Requirements =
                        {
                            Requirements.Features.ProofKeyForCodeExchange
                        }
                });
            }
        }

        public static async Task RegisterScopesAsync(IServiceProvider provider)
        {
            var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

            if (await manager.FindByNameAsync("api1") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "api1",
                    Resources =
                {
                    "resource_server_1"
                }
                });
            }

            if (await manager.FindByNameAsync("api2") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "api2",
                    Resources =
                {
                    "resource_server_2"
                }
                });
            }

            if (await manager.FindByNameAsync("dataEventRecords") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    DisplayName = "dataEventRecords API access",
                    DisplayNames =
                        {
                            [CultureInfo.GetCultureInfo("fr-FR")] = "Accès à l'API de démo"
                        },
                    Name = "dataEventRecords",
                    Resources =
                        {
                            "rs_dataEventRecordsApi"
                        }
                });
            }
        }
    }
}
