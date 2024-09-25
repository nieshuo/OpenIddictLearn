using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using OpenIddict.Abstractions;
using OpenIddict.Server.Data;
using OpenIddict.Server.Models;
using OpenIddictLearn.Server;
using Quartz;
using System.Globalization;
using System.Reflection;
using System.Security.Claims;

namespace OpenIddict.Server
{
    public class Startup
    {
        private readonly string swaggerName = "v1";
        private readonly string swaggerTitle = "OpenIddictLearnApi文档";
        private readonly string swaggerVersion = "1.0.0";
        public IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // 数据库连接地址
            var connection = Configuration.GetConnectionString("OpenIddictLearn_db");
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                // Configure the context to use sqlite.
                //options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-hollastin-server.sqlite3")}");
                options.UseSqlServer(connection);
                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

            services.AddControllers()
                    .AddNewtonsoftJson(options =>
                    {
                        options.SerializerSettings.ContractResolver = new DefaultContractResolver();//序列化时key为驼峰样式
                        //options.SerializerSettings.DateTimeZoneHandling = DateTimeZoneHandling.Local;
                        //options.SerializerSettings.DateFormatString = "yyyy-MM-dd HH:mm:ss";
                        options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;//忽略循环引用
                    });
            #region 国际化
            services.AddLocalization(options =>
            {
                // options.ResourcesPath = "Resources";
            });

            services.Configure<RequestLocalizationOptions>(options =>
            {
                var supportedCultures = new List<CultureInfo>
                {
                    new CultureInfo("en-US"),
                    new CultureInfo("zh-CN")
                };

                options.DefaultRequestCulture = new RequestCulture("zh-CN");
                options.SupportedCultures = supportedCultures;
                options.SupportedUICultures = supportedCultures;
            });
            #endregion


            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 6;
            }).AddEntityFrameworkStores<ApplicationDbContext>()
              .AddDefaultTokenProviders();

            services.AddCors(options =>
            {
                // this defines a CORS policy called "default"
                options.AddPolicy("AllowAllOrigins", builder =>
                {
                    //builder.AllowAnyOrigin()
                    builder.WithOrigins("http://192.168.97.158:3000", "http://116.62.149.236:8081")
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials();
                });
            });

            // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
            // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
            services.AddQuartz(options =>
            {
                options.UseSimpleTypeLoader();
                options.UseInMemoryStore();
            });

            // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
            services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

            services.AddOpenIddict()
                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the Entity Framework Core stores and models.
                    // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                    options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>();
                    //喜欢使用MongoDB的开发人员可以删除前面的代码行并配置OpenIddict使用指定的MongoDB数据库:
                    // options.UseMongoDb() .UseDatabase(new MongoClient().GetDatabase("openiddict"));

                    // Enable Quartz.NET integration.
                    options.UseQuartz();
                })
                .AddClient(options =>
                {
                    options.UseWebProviders()
                        .AddWeibo(options =>
                        {
                            options.SetClientId("")
                                .SetClientSecret("")
                                .SetRedirectUri("");
                        });
                })
                // Register the OpenIddict server components.
                .AddServer(options =>
                {
                    // Enable the token endpoint.
                    options.SetAuthorizationEndpointUris("/connect/authorize");
                    options.SetDeviceEndpointUris("/connect/device");
                    options.SetIntrospectionEndpointUris("/connect/introspect");
                    options.SetRevocationEndpointUris("/connect/revocat");
                    options.SetUserinfoEndpointUris("/connect/userinfo");
                    options.SetVerificationEndpointUris("/connect/verify");
                    options.SetLogoutEndpointUris("/connect/logout");
                    options.SetTokenEndpointUris("/connect/token");

                    // 这是允许的模式
                    // Enable the password flow.
                    options.AllowAuthorizationCodeFlow()
                           .AllowClientCredentialsFlow()
                           .AllowDeviceCodeFlow()
                           .AllowHybridFlow()
                           .AllowImplicitFlow()
                           .AllowPasswordFlow()
                           .AllowRefreshTokenFlow();

                    // Accept anonymous clients (i.e clients that don't send a client_id).
                    options.AcceptAnonymousClients();

                    // 令牌的加密和签名
                    options.AddEphemeralEncryptionKey()
                        .AddEphemeralSigningKey();
                    //.DisableAccessTokenEncryption();//解除accesstoken加密

                    // Register the signing and encryption credentials.
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    //会使access_token和refresh_token长度变短
                    //options.UseReferenceAccessTokens()
                    //        .UseReferenceRefreshTokens();

                    // Register your scopes - Scopes are a list of identifiers used to specify
                    // what access privileges are requested.
                    options.RegisterScopes(
                        OpenIddictConstants.Scopes.OfflineAccess,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                        "api1");

                    // Set the lifetime of your tokens
                    options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
                    options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

                    // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                    options.UseAspNetCore()
                           .DisableTransportSecurityRequirement()   //解除https限制 
                           .EnableAuthorizationEndpointPassthrough()
                           .EnableLogoutEndpointPassthrough()
                           .EnableTokenEndpointPassthrough()
                           .EnableUserinfoEndpointPassthrough()
                           .EnableStatusCodePagesIntegration();
                })

                // Register the OpenIddict validation components.
                .AddValidation(options =>
                {
                    // Import the configuration from the local OpenIddict server instance.
                    options.UseLocalServer();

                    // Register the ASP.NET Core host.
                    options.UseAspNetCore();
                });

            // Register the worker responsible for creating and seeding the SQL database.
            // Note: in a real world application, this step should be part of a setup script.
            services.AddHostedService<Worker>();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                //Bearer 的scheme定义
                var securityScheme = new OpenApiSecurityScheme()
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    //参数添加在头部
                    In = ParameterLocation.Header,
                    //使用Authorize头部
                    Type = SecuritySchemeType.Http,
                    //内容为以 bearer开头
                    Scheme = "bearer",
                    BearerFormat = "JWT"
                };

                //把所有方法配置为增加bearer头部信息
                var securityRequirement = new OpenApiSecurityRequirement
                {{
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "bearerAuth"
                        }
                    },
                    new string[] {}
                }};

                //注册到swagger中
                c.AddSecurityDefinition("bearerAuth", securityScheme);
                c.AddSecurityRequirement(securityRequirement);
                c.SwaggerDoc(swaggerName, new OpenApiInfo
                {
                    Title = swaggerTitle,
                    Version = swaggerVersion,
                    Description = $"接口描述"
                });

                //Locate the XML file being generated by ASP.NET...
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.XML";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);

                //... and tell Swagger to use those XML comments.    
                //true:显示控制器层注释
                c.IncludeXmlComments(xmlPath, true);
                //对action的名称进行排序，如果有多个，就可以看见效果了
                c.OrderActionsBy(x => x.RelativePath);
            });
        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
            }
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(env.ContentRootPath, "")),
                RequestPath = ""
            });
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint($"/swagger/{swaggerName}/swagger.json", $"{swaggerTitle + ":" + swaggerVersion}");
            });

            app.UseDeveloperExceptionPage();

            app.UseRouting();
            #region 国际化
            app.UseRequestLocalization();
            #endregion

            app.UseCors("AllowAllOrigins");

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapDefaultControllerRoute();
            });

            app.UseWelcomePage();
        }
    }
}
