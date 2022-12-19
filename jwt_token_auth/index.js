const uuid = require('uuid');
const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');

const app = express();
dotenv.config();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';
const JWT_KEY = "1337"

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
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

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session(); 

app.use((req, res, next) => {
    let currentSession = {};
    let jwtToken = req.get(SESSION_KEY);
    
    if (jwtToken) {
        const verifiedToken = jwt.verify(jwtToken, JWT_KEY);
        console.log(verifiedToken)
        let sessionId = verifiedToken.sub

        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
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

app.get('/', (req, res) => {
    let jwtToken = req.get(SESSION_KEY);
    
    if (jwtToken) {
        return res.json({
            username: jwt.verify(jwtToken, JWT_KEY).name,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'admin',
        password: 'admin',
        username: 'Admin1337',
    }
]

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;
    
    const user = users.find((user) => {
        if (user.login == login && user.password == password) {
            return true;
        }
        return false
    });

    if (user) {
        req.session.username = user.username;
        req.session.login = user.login;

        var d = new Date();
        var calculatedExpiresIn = (((d.getTime()) + (60 * 60 * 1000)) - (d.getTime() - d.getMilliseconds()) / 1000);

        let data = {
        "sub": req.sessionId,
        "name": user.username,
        "iat": (d.getTime())
        }
    
        const token = jwt.sign(data, JWT_KEY, { expiresIn: calculatedExpiresIn });

        res.json({ token: token });
    }

    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
