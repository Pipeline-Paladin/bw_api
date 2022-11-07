const express = require("express");
const oauth2 = require("express-oauth2-jwt-bearer");
const opa = require("./opa.js");

const app = express();

const userRouter = express.Router();
const adminRouter = express.Router();

const process = require("process");
const keycloakUrl = process.env["KEYCLOAK_URL"];
console.log(keycloakUrl)

app.use(oauth2.auth({
    issuerBaseURL: keycloakUrl + "/realms/taime",
    issuer: keycloakUrl + "/realms/taime",
    jwksUri: keycloakUrl + "/realms/taime/protocol/openid-connect/certs",
    audience: "account"
}));

app.use("/api/user", userRouter);
app.use("/api/admin", adminRouter);

userRouter.use(async (req, res, next) => {
    if(await opa.verify("taime/auth/user", "/api/user/" + req.path, req.auth.token))
    {
        next()
    }
    else
    {
        res.status(403).send({status: 403, message: "You do not have access."});
    }
});

adminRouter.use(async (req, res, next) => {
    if(await opa.verify("taime/auth/admin", "/api/admin/" + req.path, req.auth.token))
    {
        next()
    }
    else
    {
        res.status(403).send({status: 403, message: "You do not have access."});
    }
});

userRouter.get("/", (req, res) => {
    res.send({status: 200, message: "OK"})
});

userRouter.get("/day", (req, res) => {
    res.send({status: 200, message: "We think it is Tuesday, with an accuracy of 14.29%."})
});

adminRouter.get("/", (req, res) => {
    res.send({status: 200, message: "OK"})
});

adminRouter.get("/status", (req, res) => {
    res.send({status: 200, message: "Everything seems to be online"})
});

// Register policies
opa.register("taime/auth/user", "./policies/user.rego")
opa.register("taime/auth/admin", "./policies/admin.rego")

app.listen(8081);
