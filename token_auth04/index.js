const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const auth0 = require('auth0')
const jwt = require('jsonwebtoken')
const dotenv = require("dotenv");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
dotenv.config();

const SESSION_KEY = process.env.SESSION_KEY;
const port = process.env.PORT;
const host = process.env.HOST;

const AuthenticationClient = new auth0.AuthenticationClient(
    {
        domain: process.env.DOMAIN,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET
    }
);

const ManagementClient = new auth0.ManagementClient(
    {
        domain: process.env.DOMAIN,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET
    }
)

app.use(async (req, res, next) => {
    let authorization = req.get(SESSION_KEY);

    if (authorization) {
        let tokens = authorization.split(';');
        if (tokens.length === 3) {
            req.access_token = tokens[0];
            req.refresh_token = tokens[1];
            req.id_token = tokens[2];
        }
        try {
            let payload = jwt.decode(req.id_token);

            if (Date.now() >= payload.exp * 1000) {
                console.log('expired', payload.exp);

                let refreshRequest = await AuthenticationClient.refreshToken(
                    {
                        refresh_token: req.refresh_token
                    }
                );

                req.access_token = refreshRequest.access_token;
                req.id_token = refreshRequest.id_token;

                console.log("refreshed", refreshRequest);
            }
        } catch (err) {
            res.status(401).send();
            console.log(err);
            return;
        }

        res.headers = {Authorization: `${req.access_token};${req.refresh_token};${req.id_token}`}
    }

    next();
});

app.get('/', (req, res) => {
    if (req.access_token) {
        let payload = jwt.decode(req.id_token);

        return res.json({
            username: payload.nickname,
            logout: `http://${host}:${port}/logout`
        })
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    sessionStorage.clear()

    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    let loginResult = {};

    try {
        loginResult = await auth0Login(login, password);
    } catch (err) {
        res.status(401).send();
        console.log(err);
        return;
    }
    console.log(loginResult);

    res.json({
        access_token: loginResult.access_token,
        refresh_token: loginResult.refresh_token,
        id_token: loginResult.id_token
    });
});


app.post('/api/signup', async (req, res) => {
    const {email, password} = req.body;
    let createResult = {}

    try {
        createResult = await ManagementClient.createUser(
            {
                email: email,
                password: password,
                connection: process.env.REALM
            }
        );

        if (createResult instanceof Error) {
            throw createResult;
        }
    } catch (err) {
        res.status(400).send();
        console.log(err);
        return;
    }

    console.log(createResult)

    let loginResult = {};

    try {
        loginResult = await auth0Login(email, password);
    } catch (err) {
        res.status(401).send();
        console.log(err);
        return;
    }
    console.log(loginResult);

    res.json({
        access_token: loginResult.access_token,
        refresh_token: loginResult.refresh_token,
        id_token: loginResult.id_token
    });
});

async function auth0Login(login, password) {
    const data = {
        client_id: process.env.CLIENT_ID,
        username: login,
        password: password,
        realm: process.env.REALM,
        scope: 'offline_access'
    };

    return AuthenticationClient.passwordGrant(data);
}

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
});
