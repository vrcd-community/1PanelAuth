using System.IO.Compression;
using System.Net.Http.Headers;
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

app.MapForwarder("{**catch-all}", forwarderOptions.Endpoint, context =>
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

    context.AddRequestHeader("Accept-Encoding", "gzip, deflate, br", false);

    context.AddResponseTransform(async responseTransformContext =>
    {
        if (responseTransformContext.ProxyResponse is null)
            return;

        var clientPreferEncodings = responseTransformContext.HttpContext.Request.Headers.AcceptEncoding.ToString()
            .Trim().Replace(" ", "").Split(',');
        var responseEncoding = clientPreferEncodings.Contains("br") ? "br" :
            clientPreferEncodings.Contains("gzip") ? "gzip" :
            clientPreferEncodings.Contains("deflate") ? "deflate" : "none";

        var originContent = responseTransformContext.ProxyResponse.Content;
        var response = responseTransformContext.HttpContext.Response;

        response.Headers.Server = "1PanelAuth";
        responseTransformContext.ProxyResponse.Headers.Server.Clear();
        responseTransformContext.ProxyResponse.Headers.Server.Add(new ProductInfoHeaderValue("1PanelAuth", null));

        if (originContent.Headers.ContentType?.MediaType != "text/html")
        {
            if (clientPreferEncodings.Contains(originContent.Headers.ContentEncoding.FirstOrDefault()))
                return;

            responseTransformContext.SuppressResponseBody = true;
            await using var contentStream = await GetHttpContentDecodeStreamAsync(originContent);

            response.ContentLength = null;

            if (responseEncoding == "none")
            {
                response.Headers.Remove("Content-Encoding");
                await contentStream.CopyToAsync(response.Body);
            }

            response.Headers.ContentEncoding = responseEncoding;
            await using var compressStream = GetCompressStream(response.Body, responseEncoding);

            await contentStream.CopyToAsync(compressStream);

            return;
        }

        if (!originContent.Headers.ContentEncoding.Any(IsSupportedEncoding))
        {
            return;
        }

        var rawHtml = await DecodingHttpContentAsync(originContent);

        responseTransformContext.SuppressResponseBody = true;

        var htmlDoc = new HtmlDocument();
        htmlDoc.LoadHtml(rawHtml);

        var scriptElement = htmlDoc.CreateElement("script");
        scriptElement.Attributes.Add("type", "module");
        scriptElement.InnerHtml =
            """
            const globalStateRaw = localStorage.getItem('GlobalState')

            if (globalStateRaw) {
                updateGlobalState()
            } else {
                const observer = new MutationObserver(e => {
                    if (e[0].removedNodes) {
                        observer.disconnect()
                        setTimeout(() => {
                            if (localStorage.getItem('GlobalState')) {
                                updateGlobalState()
                                location.reload()
                            }
                        }, 1000)
                    }
                })
                
                observer.observe(document.querySelector("#app"), {
                    childList: true
                })
            }
            
            function updateGlobalState() {
                const globalStateRaw = localStorage.getItem('GlobalState')
                let globalState = JSON.parse(globalStateRaw)
            
                if (!globalState.isLogin) {
                    globalState.isLogin = true
                    localStorage.setItem('GlobalState', JSON.stringify(globalState))
                    
                    location.reload()
                }
            }
            """;

        htmlDoc.DocumentNode.SelectSingleNode("//body")?.AppendChild(scriptElement);

        var responseHtml = htmlDoc.DocumentNode.OuterHtml;

        if (!clientPreferEncodings.Any(IsSupportedEncoding))
        {
            response.Headers.Remove("Content-Encoding");

            response.ContentLength = null;
            await using var streamWriter = new StreamWriter(response.Body);
            await streamWriter.WriteAsync(responseHtml);
            await streamWriter.FlushAsync();

            return;
        }

        await using var responseContentStream = new MemoryStream();
        await using var responseContentStreamWriter = new StreamWriter(responseContentStream);

        await responseContentStreamWriter.WriteAsync(responseHtml);
        await responseContentStreamWriter.FlushAsync();

        responseContentStream.Seek(0, SeekOrigin.Begin);

        response.Headers.ContentEncoding = responseEncoding;
        response.ContentLength = null;

        await using var compressResponseStream = GetCompressStream(response.Body, responseEncoding);
        await responseContentStream.CopyToAsync(compressResponseStream);
    });
});

app.Run();

async ValueTask<string> DecodingHttpContentAsync(HttpContent httpContent)
{
    await using var decodeStream = await GetHttpContentDecodeStreamAsync(httpContent);
    using var streamReader = new StreamReader(decodeStream);

    return await streamReader.ReadToEndAsync();
}

async ValueTask<Stream> GetHttpContentDecodeStreamAsync(HttpContent httpContent)
{
    var contentStream = await httpContent.ReadAsStreamAsync();
    if (httpContent.Headers.ContentEncoding.FirstOrDefault() is not { } encoding)
    {
        return contentStream;
    }

    return GetDecompressStream(contentStream, encoding);
}

Stream GetDecompressStream(Stream contentStream, string encoding)
{
    return encoding switch
    {
        "gzip" => new GZipStream(contentStream, CompressionMode.Decompress),
        "deflate" => new DeflateStream(contentStream, CompressionMode.Decompress),
        "br" => new BrotliStream(contentStream, CompressionMode.Decompress),
        _ => contentStream
    };
}

Stream GetCompressStream(Stream outputStream, string encoding)
{
    return encoding switch
    {
        "gzip" => new GZipStream(outputStream, CompressionLevel.Optimal),
        "deflate" => new DeflateStream(outputStream, CompressionLevel.Optimal),
        "br" => new BrotliStream(outputStream, CompressionLevel.Optimal),
        _ => throw new NotSupportedException("The encoding is not supported.")
    };
}

bool IsSupportedEncoding(string encoding)
{
    return encoding is "gzip" or "deflate" or "br";
}

internal class ForwarderOptions
{
    public string Endpoint { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = [];
}
