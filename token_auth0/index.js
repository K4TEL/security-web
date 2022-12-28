import { v4 } from "uuid";
import { join, dirname } from "path";
import bodyParser from "body-parser";
import fetch, { Headers } from "node-fetch";
import express from "express";
import onFinished from "on-finished";
import { fileURLToPath } from 'url';
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import { readFileSync, writeFileSync } from "fs";

if (!globalThis.fetch) {
    globalThis.Headers = Headers
}

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SESSION_KEY = process.env.SESSION_KEY;
const port = process.env.PORT;
const host = process.env.HOST;
const REFRESH_DELAY = 5;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

class Session {
    #sessions = {};
    #savePath;

    constructor(savePath) {
        this.#savePath = savePath;
        try {
            this.#sessions = readFileSync(this.#savePath, 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
            console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        writeFileSync(this.#savePath, JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init() {
        const sessionId = v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session(join(__dirname, './sessions.json'));

const refreshUserToken = async (refreshToken) => {
    const bodyParams = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        refresh_token: refreshToken,
    });
    return await fetch(`https://${process.env.DOMAIN}/oauth/token`, {
        method: "POST",
        body: bodyParams,
    });
};

const isTokenExpired = (accessToken, minDelay = 0) => {
    const { exp } = jwt.decode(accessToken);
    const now = Math.floor(Date.now() / 1e3);
    console.log({exp, now});
    return exp - now < minDelay;
};

app.use(async (req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);
    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init();
        } else if (
            currentSession.login && 
            isTokenExpired(currentSession.accessToken, REFRESH_DELAY)
        ) {
            const response = await refreshUserToken(currentSession.refreshToken);
            if (!response.ok) {
                console.error(`Could not refresh token: ${await response.text()}`);
            }
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

app.get("/", (_, res) => {
    res.sendFile(join(__dirname, "/index.html"));
});

app.get("/login", (_, res) => {
    res.sendFile(join(__dirname, "/login.html"));
});

app.get("/logout", (_, res) => {
    res.sendFile(join(__dirname, "/logout.html"));
});

app.get("/signup", (_, res) => {
    res.sendFile(join(__dirname, "/signup.html"));
});

app.get("/api/status", (req, res) => {
    res.json({
        status: req.session.login
        ? `User ${req.session.login} is logged in!`
        : "User is not logged in!",
    });
});

const loginUser = async (login, password) => {
    const bodyParams = new URLSearchParams({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: login,
        password: password,
        realm: process.env.REALM,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        audience: process.env.AUDIENCE,
        scope: "offline_access",
    });
    return await fetch(`https://${process.env.DOMAIN}/oauth/token`, {
        method: "POST",
        body: bodyParams,
    }); 
};

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    const response = await loginUser(login, password);
    if (response.ok) {
        const auth = await response.json();
        req.session.login = login;
        req.session.accessToken = auth.access_token;
        req.session.refreshToken = auth.refresh_token;

        console.log(
            `Seccessfull login!\nAccess token: ${auth.access_token}\nRefresh token: ${auth.refresh_token}`
        );
        res.status(200).json({ token: req.sessionId });
    } else {
        const errorText = await response.text();
        console.error(`Login failed: ${errorText}`);
        res.status(response.status).json(JSON.parse(errorText));
    }
});

const createUser = async (login, password, accessToken) => {
    const bodyParams = JSON.stringify({
        email: login,
        password: password,
        connection: process.env.REALM,
        verify_email: false,
        blocked: false,
        email_verified: false
    });
    const headers = new Headers();
    headers.append("Content-Type", "application/json");
    headers.append("Authorization", `Bearer ${accessToken}`);
    
    return await fetch(`https://${process.env.DOMAIN}/api/v2/users`, {
        method: "POST",
        body: bodyParams,
        headers: headers,
    });
};

app.post("/api/signup", async (req, res) => {
    const {login, password} = req.body;
    await refreshAppToken();
    const accessToken = app.get("accessToken");
    console.log(`App token: ${accessToken}`);
    const response = await createUser(login, password, accessToken);
    if (response.ok) {
        res.status(201).send({ token: req.sessionId });
    } else {
        const errorText = await response.text();
        console.error(`Failed to create user: ${errorText}`);
        res.status(response.status).json(JSON.parse(errorText));
    }
});

app.get("/api/logout", async (req, res) => {
    if (req.session.login) {
        console.log(`User ${req.session.login} logged out`);
        sessions.destroy(req);
    }
    res.sendStatus(204);
})

const loginApp = async () => {
    const bodyParams = new URLSearchParams({
        grant_type: "client_credentials",
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        audience: process.env.AUDIENCE,
    });
    return await fetch(`https://${process.env.DOMAIN}/oauth/token`, {
        method: "POST",
        body: bodyParams,
    });  
};

const refreshAppToken = async () => {
    const accessToken = app.get("accessToken");
    if (accessToken && isTokenExpired(accessToken, REFRESH_DELAY)) {
        return;
    }
    const response = await loginApp();
    if (response.ok) {
        const tokenData = await response.json();
        app.set("accessToken", tokenData.access_token);
        console.log(`Token scope: ${tokenData.scope}`);
    } else {
        console.error(
            `App is not recognized by Auth0: ${await response.text()}`
            );
        process.exit(1);
    }
};

app.listen(port, host, async () => {
    console.log(`Example app listening on port ${port}`);
    await refreshAppToken();
    console.log(`App token: ${app.get("accessToken")}`);
});
