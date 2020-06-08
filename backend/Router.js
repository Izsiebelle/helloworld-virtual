const bcrypt = require('bcrypt');

class Router {

    constructor(app, db) {
        this.login(app,db);
        this.register(app, db);
        this.logOut(app, db);
        this.isLoggedIn(app, db);
    }

    login(app, db) {
        
        app.post('/login', (req, res) => {
            let username = req.body.username;
            let password = req.body.password;

            let cols = [username];
            db.query('SELECT * FROM users WHERE username = ? LIMIT 1', cols, (err, data, fields) => {
                if(err) {
                    res.json({
                        success: false,
                        msg: "Username not found"
                    })
                    return; 
                }

                //If found check password
                if(data && data.length === 1) {
                    bcrypt.compare(password, data[0].password, (bcryptErr, verified) => {

                        if (verified) {
                            req.session.userID = data[0].id;
                            res.json({
                                sucess: true,
                                username: data[0].username
                            })
                            return;
                        } else {
                            res.json({
                                success: false,
                                msg: 'password not verified'
                            })
                        }
                    });
                } else {
                    res.json({
                        success: false,
                        msg: "User does not exist"
                    })
                }
            });
        })
    }

    register(app, db) {
        app.post('/register', async(req, res) => {

            const saltRounds = 10;
            const password = req.body.password;
            const encryptedPassword = await bcrypt.hash(password, saltRounds)
            var users={
                "first_name": req.body.first_name,
                "last_name": req.body.last_name,
                "username": req.body.username,
                "email":req.body.email,
                "password":encryptedPassword
            }
            
            db.query('INSERT INTO users SET ?', users, function (error, results, fields) {
                if (error) {
                    res.json({
                        success: false,
                        msg: "Something went wrong"
                    })
                } else {
                res.json({
                    sucess: true,
                    });
                }
            });
        })
    }

    logOut(app, db) {
        app.post('/logout', (req,res) => {

            if(req.session.userID) {

                req.session.destroy();
                res.json({
                    sucess: true
                })
                return true
            } else {
                res.json({
                    sucess: false
                })
                return false;
            }
        });
    }

    isLoggedIn(app, db) {

        app.post('/isLoggedIn', (req, res) => {

            if(req.session.userID) {
                let cols = [req.session.userID];
                db.query('SELECT * FROM users WHERE id = ? LIMIT 1', cols, (err, data, fields) => {

                    if(data && data.length === 1) {
                        res.json({
                            success: true,
                            username: data[0].username
                        })
                        return true
                    } else {
                        res.json({
                            sucess: false
                        })
                    }
                });
            } else {
                res.json({
                    success: false
                })
            }
        })
    }


}

module.exports = Router;