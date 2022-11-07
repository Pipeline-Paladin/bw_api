const fs = require("fs");

const axios = require("axios");

const process = require("process");
const opaUrl = process.env["OPA_URL"];

module.exports.register = async (policy, regoFile) => {
    const rego = fs.readFileSync(regoFile).toString();
    const res = await axios.put(opaUrl + "/v1/policies/" + policy, rego);
}

module.exports.verify = async (policy, path, token) => {
    const input = {
        input: {
            path: path,
            token: token
        }
    }
    const res = await axios.post(opaUrl + "/v1/data/" + policy, input);
    return res.data.result.allow
}
