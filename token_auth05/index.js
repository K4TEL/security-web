const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const auth0 = require('auth0')
const jwt = require('jsonwebtoken')
const {auth} = require('express-oauth2-jwt-bearer');
const dotenv = require("dotenv");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
dotenv.config();

const AUTHORIZATION_KEY = 'Authorization';

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
    let authorization = req.get(AUTHORIZATION_KEY);
    let refresh = req.get('Refresh');

    if (authorization) {
        console.log(authorization);
        req.access_token = authorization.split(' ')[1];
        req.refresh_token = refresh;
        try {
            let payload = jwt.decode(req.access_token);
            console.log(payload)

            if (Date.now() >= payload.exp * 1000) {
                console.log('expired', payload.exp);

                let refreshRequest = await AuthenticationClient.refreshToken(
                    {
                        refresh_token: req.refresh_token
                    }
                );

                req.access_token = refreshRequest.access_token;

                console.log("refreshed", refreshRequest);
            }
        } catch (err) {
            console.log(err)
            res.status(401).send();
            return;
        }

        res.headers = {Authorization: `${req.access_token};${req.refresh_token}`}
    }

    next();
});

app.get('/', (req, res) => {
    if (req.access_token) {
        let payload = jwt.decode(req.access_token);

        return res.json({
            username: payload.sub,
            logout: `http://${host}:${port}/logout`
        })
    }
    res.sendFile(path.join(__dirname + '/index.html'));
})

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
        refresh_token: loginResult.refresh_token
    });
});

const checkJwt = auth({
    audience: process.env.AUDIENCE,
    issuerBaseURL: `https://${process.env.DOMAIN}`,
});

app.get('/api/private', checkJwt, (req, res) => {
    res.json({
        message: 'Private message'
    })
})


app.post('/api/signup', async (req, res) => {
    const {email, password} = req.body;
    let createResult = {}

    try {
        createResult = await ManagementClient.createUser(
            {
                email: email,
                password: password,
                connection: 'Username-Password-Authentication'
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
        audience: process.env.AUDIENCE,
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
})
