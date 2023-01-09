const express = require('express');
const querystring = require('querystring');
const bodyParser = require('body-parser');
const auth0 = require('auth0')
const jwt = require('jsonwebtoken')
const {auth} = require('express-oauth2-jwt-bearer');
const dotenv = require("dotenv");
const axios = require("axios").default;
var request = require("request");
const { query } = require('express');

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
);


app.use(async (req, res, next) => {
    let authorization = req.get(AUTHORIZATION_KEY);
    let refresh = req.get('Refresh');

    console.log(authorization);

    if (authorization) {
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
    } else {
        console.log(req, res);
    const uri = new URL(`https://${process.env.DOMAIN}/authorize`);

    uri.searchParams.append('client_id', process.env.CLIENT_ID);
    uri.searchParams.append('redirect_uri', `http://${host}:${port}/callback`);
    uri.searchParams.append('response_type', 'code');
    uri.searchParams.append('response_mode', 'query');
    uri.searchParams.append('scope', 'offline_access');
    uri.searchParams.append('connection', process.env.REALM);

    res.redirect(uri.toString());
    }
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
        refresh_token: loginResult.refresh_token
    });
});

app.get('/callback', async (req, res) => {
    const code = req.query.code;
    console.log(code);

    var options = {
        method: 'POST',
        url: `https://${process.env.DOMAIN}/oauth/token`,
        headers: {'content-type': 'application/x-www-form-urlencoded'},
        data: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: `http://${host}:${port}/callback`,
          audience: process.env.AUDIENCE,
          client_id: process.env.CLIENT_ID,
          client_secret: process.env.CLIENT_SECRET,
          scope: "offline_access"
        })
      };

      let tokenResult = {};

      await axios.request(options).then(function (response) {
        tokenResult = response.data;
      }).catch(function (error) {
        console.error(error);
      });

      console.log(tokenResult.access_token);
      console.log(tokenResult.refresh_token);

      res.status(200).send();
});

const checkJwt = auth({
    audience: process.env.AUDIENCE,
    issuerBaseURL: `https://${process.env.DOMAIN}`,
});

app.get('/api/private', checkJwt, (req, res) => {
    res.json({
        message: 'Private message'
    })
});


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
