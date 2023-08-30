import http from "http";
import fs from "fs/promises";

await loadEnv();
const server = http.createServer(handleRequest);

server.listen(3000, "127.0.0.1", () => {
  console.log("Server started on port 3000");
});

const host = "http://localhost:3000";

async function handleRequest(
  request: http.IncomingMessage,
  response: http.ServerResponse
): Promise<void> {
  const url = new URL(request.url ?? "/", host);
  const pathname = url.pathname;
  switch (pathname) {
    case "/": {
      response.write("/login/github to login with Github!");
      response.end();
      return;
    }
    case "/login/github": {
      return await handleAuthorization(request, response);
    }
    case "/login/github/callback": {
      return await handleCallback(request, response);
    }
  }
  response.statusCode = 404;
  response.end();
}

async function handleAuthorization(
  _: http.IncomingMessage,
  response: http.ServerResponse
): Promise<void> {
  const state = "abc";
  const authorizationUrl = new URL("https://github.com/login/oauth/authorize");
  authorizationUrl.searchParams.set(
    "client_id",
    process.env.GITHUB_CLIENT_ID ?? ""
  );
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("state", state);
  response.setHeader("Location", authorizationUrl.toString());
  response.setHeader(
    "Set-Cookie",
    `state=${state}; Path=/; Max-Age=3600; HttpOnly`
  );
  response.statusCode = 302;
  response.end();
}

async function handleCallback(
  request: http.IncomingMessage,
  response: http.ServerResponse
): Promise<void> {
  const url = new URL(request.url ?? "/", host);
  const state = url.searchParams.get("state");
  const cookies = parseCookie(request.headers.cookie ?? "");
  const storedCookie = cookies.get("state") ?? null;
  if (!state || state !== storedCookie) {
    response.statusCode = 403;
    response.end();
    return;
  }
  const code = url.searchParams.get("code") ?? "";
  const accessToken = await exchangeAuthorizationCode(code);
  const githubUser = await getGithubUser(accessToken);
  response.write(`User ID: ${githubUser.id}\nUsername: ${githubUser.login}`);
  response.end();
}

async function exchangeAuthorizationCode(code: string): Promise<string> {
  const body = new URLSearchParams();
  body.set("client_id", process.env.GITHUB_CLIENT_ID ?? "");
  body.set("client_secret", process.env.GITHUB_CLIENT_SECRET ?? "");
  body.set("grant_type", "code");
  body.set("code", code);
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    body,
    headers: {
      Accept: "application/json",
    },
  });
  const { access_token: accessToken } = (await response.json()) as {
    access_token: string;
  };
  return accessToken;
}

interface GithubUser {
  login: string;
  id: string;
}

async function getGithubUser(accessToken: string): Promise<GithubUser> {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "typescript",
    },
  });
  if (!response.ok) {
    throw new Error("Failed to fetch user");
  }
  const user = (await response.json()) as GithubUser;
  return user;
}

function parseCookie(cookie: string): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const item of cookie.split(";")) {
    const [key, ...valueSegments] = item.split("=");
    cookies.set(key, valueSegments.join("="));
  }
  return cookies;
}

async function loadEnv(): Promise<void> {
  const file = await fs.readFile("../.env");
  for (const line of file.toString().split("\n")) {
    const [key, ...valueSegments] = line.split("=");
    let value = valueSegments.join("=");
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}
