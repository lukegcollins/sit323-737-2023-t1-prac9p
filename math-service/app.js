const express = require('express');
const app = express();
const port = 3000;

const passport = require('passport');
require('./passport.js')(passport);

const authorizationMap = new Map();
authorizationMap.set("addition", 0b0001);
authorizationMap.set("multiplication", 0b0010);
authorizationMap.set("subtraction", 0b0100);
authorizationMap.set("division", 0b1000);

app.use(express.json());
app.use((err, req, res, next) => {
    res.status(400).json({ status: 400, message: "Invalid JSON format" })
});

function addition(a, b) { return a + b }
function multiplication(a, b) { return a * b }
function subtraction(a, b) { return a - b }
function division(a, b) { return a / b }

function performMath(req, res, callback) {
    const { num1, num2 } = req.body;
    if (isNaN(num1) || isNaN(num2)) {
        return res.status(400).json({ status: 400, message: "Invalid parameters (non-numeric)" });
    }
    return res.status(400).json({ status: 400, message: "Invalid parameters (non-numeric)" });
}
var result = callback(parseFloat(num1), parseFloat(num2));
res.status(200).json({ status: 200, type: callback.name, input: [num1, num2], result: result });
}

function authorizeAction(req, res, callback) {
    let value = authorizationMap.get(callback.name) & req.user.access; // perform bitwise AND on user access and required access
    if (value == 0) return res.status(403).json({ status: 403, message: "Unauthorized action" });
    performMath(req, res, callback);
}

app.use(passport.initialize());

// Authenticates supplied token and provides custom error messages
function authenticateToken(req, res, next) {
    passport.authenticate('jwt', { session: false }, (error, user, info) => {
        if (user == false) {
            if (info.name === "TokenExpiredError") return res.status(400).json({ status: 400, message: "Authentication Failure: Expired token" });
            if (info.name === "JsonWebTokenError") return res.status(400).json({ status: 400, message: "Authentication Failure: Invalid token" });
            if (info.name === "Error") return res.status(400).json({ status: 400, message: "Authentication Failure: Missing token" });
            return res.status(400).json({ status: 400, message: "Authentication Failure: General" });
        }
        req.user = user;
        next();
    })(req, res);
}

app.post("/add", authenticateToken, (req, res) => { authorizeAction(req, res, addition); })
app.post("/multiply", authenticateToken, (req, res) => { authorizeAction(req, res, multiplication); })
app.post("/subtract", authenticateToken, (req, res) => { authorizeAction(req, res, subtraction); });
app.post("/divide", authenticateToken, (req, res) => { authorizeAction(req, res, division); })

app.use((req, res) => {
    res.sendStatus(404);
});

app.listen(port, () => console.log('listening on port:' + port));