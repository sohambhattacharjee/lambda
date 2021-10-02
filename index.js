var mysql = require('mysql');
var config = require('./config.json');
var knex = require('knex')
var crypto = require('crypto')

//create a connection
const knexConnection = knex({
    client: 'mysql',
    connection: {
        host: config.dbhost,
        user: config.dbuser,
        password: config.dbpassword,
        database: config.dbname
    }
})

const hashPassword = (password) => {
    return crypto.pbkdf2Sync(password, 'secret_salt', 1000, 64, `sha512`).toString()
}

exports.handler = async (event, context) => {
    let body;
    let statusCode = 200;
    const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "OPTIONS,POST,PUT,GET"
    };

    try {
        if (event.requestContext.http.method === "OPTIONS") {
            return {
                statusCode,
                body,
                headers
            };
        }
        let requestJSON
        if (event.body) {
            requestJSON = JSON.parse(event.body);
        }
        const { firstName, lastName, email, password, userRoleId = 2 } = requestJSON
        switch (event.requestContext.http.method) {
            case "PUT":
                if (!firstName || !lastName || !email || !password) {
                    statusCode = 400
                    body = "bad request"
                    return {
                        statusCode,
                        body,
                        headers
                    };
                }

                const userExists = await knexConnection('users').where('email', email)

                if (userExists.length > 0) {
                    statusCode = 400
                    body = "user already exists"
                    return {
                        statusCode,
                        body,
                        headers
                    };
                }
                const hashedPassword = hashPassword(password)
                const folderName = crypto.randomUUID()

                await knexConnection('users').insert({
                    first_name: firstName,
                    last_name: lastName,
                    email: email,
                    password: hashedPassword,
                    folder_name: folderName,
                    role_id: userRoleId
                })

                body = { 's3_folder': folderName, firstName, lastName, userRoleId };
                break;
            case "POST":
                if (!email || !password) {
                    statusCode = 400
                    body = "bad request"
                    break;
                }
                const exisitngUser = await knexConnection('users').where('email', email)
                if (exisitngUser.length > 0) {
                    const { first_name, last_name, password: saved_password, folder_name, role_id } = exisitngUser[0]
                    if (hashPassword(password) === saved_password) {
                        statusCode = 200
                        body = { firstName: first_name, lastName: last_name, 's3_folder': folder_name, role_id }
                        break;
                    }
                }
                statusCode = 400
                body = { error: "username or password is incorrect" }
                break;
            case "OPTIONS":
                break;
            default:
                throw new Error(`Unsupported route: "${event.requestContext.http.path}"`);
        }
    } catch (err) {
        statusCode = 400;
        body = err.message;
        return {
            statusCode,
            body,
            headers
        };
    } finally {
        body = JSON.stringify(body);
        return {
            statusCode,
            body,
            headers
        };
    }
};