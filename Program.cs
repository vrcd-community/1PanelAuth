using System.Security.Cryptography;
using System.Text;
using HtmlAgilityPack;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.AddHttpForwarder();

builder.Services.AddOptions<ForwarderOptions>()
    .Bind(builder.Configuration.GetSection("Forwarder"))
    // Token
    .Validate(options => !string.IsNullOrWhiteSpace(options.Token), "The token is required.")
    // Endpoint
    .Validate(options => !string.IsNullOrWhiteSpace(options.Endpoint), "The endpoint is required.")
    .Validate(options => Uri.TryCreate(options.Endpoint, UriKind.Absolute, out _), "The endpoint is not a valid URI.")
    .Validate(
        options =>
        {
            if (Uri.TryCreate(options.Endpoint, UriKind.Absolute, out var uri))
            {
                return uri.Scheme is "http" or "https";
            }

            return false;
        },
        "The scheme must be either 'http' or 'https'.")
    .ValidateOnStart();

var app = builder.Build();

var forwarderOptions = app.Services.GetRequiredService<IOptions<ForwarderOptions>>().Value;

app.MapForwarder("{**catch-all}", forwarderOptions.Endpoint.ToString(), context =>
{
    context.AddRequestTransform(requestTransformContext =>
    {
        foreach (var (header, value) in forwarderOptions.Headers)
        {
            requestTransformContext.ProxyRequest.Headers.Add(header, value);
        }

        return ValueTask.CompletedTask;
    });

    context.AddRequestTransform(requestTransformContext =>
    {
        requestTransformContext.ProxyRequest.Version = new Version(1, 1);
        requestTransformContext.ProxyRequest.VersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;

        return ValueTask.CompletedTask;
    });

    context.AddRequestTransform(requestTransformContext =>
    {
        var apiToken = forwarderOptions.Token;
        var unixTimeStamp = DateTimeOffset.Now.ToUnixTimeSeconds().ToString();

        var accessToken =
            Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes($"1panel{apiToken}{unixTimeStamp}")));

        requestTransformContext.ProxyRequest.Headers.Add("1panel-token", accessToken);
        requestTransformContext.ProxyRequest.Headers.Add("1panel-timestamp", unixTimeStamp);

        return ValueTask.CompletedTask;
    });

    context.AddRequestHeaderRemove("Accept-Encoding");

    context.AddResponseTransform(async responseTransformContext =>
    {
        if (responseTransformContext.ProxyResponse is not { } response)
            return;

        var originContent = response.Content;
        if (originContent.Headers.ContentType?.MediaType != "text/html")
        {
            return;
        }

        if (originContent.Headers.ContentEncoding.Count != 0)
        {
            return;
        }

        var rawHtml = await originContent.ReadAsStringAsync();

        var htmlDoc = new HtmlDocument();
        htmlDoc.LoadHtml(rawHtml);

        var scriptElement = htmlDoc.CreateElement("script");
        scriptElement.Attributes.Add("type", "module");
        scriptElement.InnerHtml =
            """
            const globalStateRaw = localStorage.getItem('GlobalState')

            if (globalStateRaw) {
                let globalState = JSON.parse(globalStateRaw)
                
                if (!globalState.isLogin) {
                    globalState.isLogin = true
                    localStorage.setItem('GlobalState', JSON.stringify(globalState))
                }
            } else {
                const observer = new MutationObserver(e => {
                    if (e[0].removedNodes) {
                        observer.disconnect()
                        setTimeout(() => {
                            if (localStorage.getItem('GlobalState')) {
                                location.reload()
                            }
                        }, 1000)
                    }
                })
                
                observer.observe(document.querySelector("#app"), {
                    childList: true
                })
            }
            """;

        htmlDoc.DocumentNode.SelectSingleNode("//body")?.AppendChild(scriptElement);

        response.Content = new StringContent(htmlDoc.DocumentNode.OuterHtml, Encoding.UTF8, "text/html");
    });
});

app.Run();

internal class ForwarderOptions
{
    public string Endpoint { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = [];
}
