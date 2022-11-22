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
    issuerBaseURL: keycloakUrl + "/realms/bw-spa",
    issuer: keycloakUrl + "/realms/bw-spa",
    jwksUri: keycloakUrl + "/realms/bw-spa/protocol/openid-connect/certs",
    audience: "account"
}));

app.use("/api/user", userRouter);
app.use("/api/admin", adminRouter);

userRouter.use(async (req, res, next) => {
    if(await opa.verify("bw-spa/auth/user", "/api/user/" + req.path, req.auth.token))
    {
        next()
    }
    else
    {
        res.status(403).send({status: 403, message: "You do not have access."});
    }
});

adminRouter.use(async (req, res, next) => {
    if(await opa.verify("bw-spa/auth/admin", "/api/admin/" + req.path, req.auth.token))
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
    res.send({status: 200, message: "het is aan het regenen in België"})
});

adminRouter.get("/", (req, res) => {
    res.send({status: 200, message: "OK"})
});

adminRouter.get("/status", (req, res) => {
    res.send({status: 200, message: "Everything seems to be online"})
});

// Register policies
opa.register("bw-spa/auth/user", "./policies/user.rego")
opa.register("bw-spa/auth/admin", "./policies/admin.rego")

app.listen(8081);
