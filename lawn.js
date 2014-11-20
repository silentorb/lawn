var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
var when = require('when');
var MetaHub = require('vineyard-metahub');
var Ground = require('vineyard-ground');
var Vineyard = require('vineyard');
var common = require('./lib/common');
var irrigation = require('./lib/irrigation');

var HttpError = common.HttpError;
var Authorization_Error = common.Authorization_Error;

var Lawn = (function (_super) {
    __extends(Lawn, _super);
    function Lawn() {
        _super.apply(this, arguments);
        this.instance_sockets = {};
        this.instance_user_sockets = {};
        this.debug_mode = false;
        this.mail = null;
        this.password_reset_template = null;
        this.services = [];
    }
    Lawn.prototype.grow = function () {
        var _this = this;
        var ground = this.ground;
        this.config.display_name_key = this.config.display_name_key || 'display_name';

        if (this.config.log_updates) {
            this.listen(ground, '*.update', function (seed, update) {
                if (update.trellis.name == 'update_log')
                    return when.resolve();

                return _this.ground.insert_object('update_log', {
                    user: update.user,
                    data: JSON.stringify(seed),
                    trellis: update.trellis.name
                });
            });
        }

        this.listen(ground, 'user.queried', function (user, query) {
            return _this.query_user(user, query);
        });

        if (this.config.mail)
            this.mail = new Lawn.Mail(this.config.mail);

        if (this.config.password_reset_template) {
            var fs = require('fs');
            this.password_reset_template = fs.readFileSync(this.config.password_reset_template, 'ascii');
        }

        this.config['valid_username'] = typeof this.config.valid_username == 'string' ? new RegExp(this.config.valid_username) : /^[A-Za-z\-_0-9]+$/;

        this.config['valid_password'] = typeof this.config.valid_password == 'string' ? new RegExp(this.config.valid_password) : /^[A-Za-z\- _0-9!@#\$%\^&\*\(\)?]+$/;

        this.config['valid_display_name'] = typeof this.config.valid_display_name == 'string' ? new RegExp(this.config.valid_display_name) : /^[A-Za-z\- _0-9!@#\$%\^&\*\(\)?]+$/;

        irrigation.grow(this);

        var gardener = require('./lib/gardener');
        gardener.grow(this);
    };

    Lawn.authorization = function (handshakeData, callback) {
        return callback(null, true);
    };

    Lawn.prototype.debug = function () {
        var args = [];
        for (var _i = 0; _i < (arguments.length - 0); _i++) {
            args[_i] = arguments[_i + 0];
        }
        var time = Math.round(new Date().getTime() / 10);
        var text = args.join(', ');
        console.log(text);
    };

    Lawn.prototype.emit_to_users = function (users, name, data) {
        return this.vineyard.bulbs.songbird.notify(users, name, data);
    };

    Lawn.prototype.notify = function (users, name, data, trellis_name) {
        return this.vineyard.bulbs.songbird.notify(users, name, data, trellis_name);
    };

    Lawn.prototype.get_user_sockets = function (id) {
        return MetaHub.map_to_array(this.instance_user_sockets[id], function (x) {
            return x;
        }) || [];
    };

    Lawn.prototype.initialize_session = function (socket, user) {
        var _this = this;
        socket.user = user;
        this.instance_sockets[socket.id] = socket;
        this.instance_user_sockets[user.id] = this.instance_user_sockets[user.id] || [];
        this.instance_user_sockets[user.id][socket.id] = socket;
        this.ground.db.query('UPDATE users SET online = 1 WHERE id = ' + user.id);

        socket.join('user/' + user.id);

        socket.on('query', function (request, callback) {
            return irrigation.process('query', request, user, _this.vineyard, socket, callback);
        });

        socket.on('update', function (request, callback) {
            return irrigation.process('update', request, user, _this.vineyard, socket, callback);
        });

        this.on_socket(socket, 'room/join', user, function (request) {
            console.log('room/join', user.id, request);
            socket.join(request.room);
        });

        this.on_socket(socket, 'room/leave', user, function (request) {
            console.log('room/leave', user.id, request);
            socket.leave(request.room);
        });

        this.on_socket(socket, 'room/emit', user, function (request) {
            console.log('room/emit', user.id, request);
            socket.broadcast.to(request.room).emit(request.event_name, request.data);
        });

        user.online = true;
        this.invoke('socket.add', socket, user);

        console.log(process.pid, 'Logged in: ' + user.id);
    };

    Lawn.prototype.query_user = function (user, query) {
        if (!this.io)
            return;

        var clients = this.io.sockets.clients(user.id);
    };

    Lawn.prototype.start = function () {
        var _this = this;
        if (!this.vineyard.bulbs.fortress)
            console.log("WARNING: Fortress is not loaded.  Server will be running with minimal security.");

        return this.ground.db.query("UPDATE users SET online = 0 WHERE online = 1").then(function () {
            _this.start_http(_this.config.ports.http);
            _this.start_sockets(_this.config.ports.websocket);
        });
    };

    Lawn.is_ready_user_object = function (user) {
        var properties = Lawn.public_user_properties;
        for (var i = 0; i < properties.length; ++i) {
            if (user[properties[i]] === undefined)
                return false;
        }

        return true;
    };

    Lawn.format_public_user = function (user) {
        return MetaHub.extend({}, user, Lawn.public_user_properties);
    };

    Lawn.format_internal_user = function (user) {
        return MetaHub.extend({}, user, Lawn.internal_user_properties);
    };

    Lawn.prototype.get_public_user = function (user) {
        if (typeof user == 'object') {
            if (Lawn.is_ready_user_object(user)) {
                return when.resolve(Lawn.format_public_user(user));
            }
        }

        var id = typeof user == 'object' ? user.id : user;
        var query = this.ground.create_query('user');
        query.add_key_filter(id);
        return query.run_single().then(function (user) {
            return Lawn.format_public_user(user);
        });
    };

    Lawn.prototype.get_schema = function (req, res, user) {
        var fortress = this.vineyard.bulbs.fortress;
        var response = !fortress || fortress.user_has_role(user, 'admin') ? this.ground.export_schema() : {};

        res.send(response);
    };

    Lawn.prototype.get_user_from_session = function (token) {
        var query = this.ground.create_query('session');
        query.add_key_filter(token);
        query.add_subquery('user').add_subquery('roles');

        return query.run_single().then(function (session) {
            if (!session)
                throw new HttpError('Session not found.', 401);

            if (session.token === 0)
                throw new HttpError('Invalid session.', 401);

            if (typeof session.user !== 'object')
                throw new HttpError('User not found.', 401);

            var user = session.user;

            return Lawn.format_internal_user(user);
        });
    };

    Lawn.prototype.http_login = function (req, res, body) {
        var _this = this;
        if (typeof body.facebook_token === 'string')
            return this.vineyard.bulbs.facebook.login(req, res, body);

        var username = body.name;
        var password = body.pass;

        var sql = "SELECT id, " + this.config.display_name_key + ", status FROM users WHERE username = ? AND password = ?";

        console.log('login', body);
        return this.ground.db.query_single(sql, [username, password]).then(function (user) {
            if (user)
                return when.resolve(user);

            var sql = "SELECT users.id, users.username, users.status, requests.password as new_password FROM users " + "\nJOIN password_reset_requests requests ON requests.user = users.id" + "\nWHERE users.username = ? AND requests.password = ?" + "\nAND requests.used = 0" + "\nAND requests.created > UNIX_TIMESTAMP() - 12 * 60 * 60";
            console.log('sql', sql);
            return _this.ground.db.query_single(sql, [username, password]).then(function (user) {
                console.log('hey', user, [username, password]);
                if (!user)
                    throw new HttpError('Invalid username or password.', 400);

                if (user.status === 0)
                    throw new HttpError('This account has been disabled.', 403);

                password = user.new_password;
                delete user.new_password;
                return _this.ground.db.query("UPDATE users SET password = ? WHERE id = ?", [password, user.id]).then(function () {
                    return _this.ground.db.query("UPDATE password_reset_requests SET used = 1, modified = UNIX_TIMESTAMP()" + "\nWHERE password = ? AND user = ?", [password, user.id]);
                }).then(function () {
                    return user;
                });
            });
        }).then(function (user) {
            if (!user)
                throw new HttpError('Invalid login info.', 400);

            if (user.status === 0)
                throw new HttpError('This account has been disabled.', 403);

            if (user.status === 2)
                throw new HttpError('This account is awaiting email verification.', 403);

            _this.invoke('user.login', user, body).then(function () {
                return Lawn.create_session(user, req, _this.ground).then(function () {
                    return _this.send_http_login_success(req, res, user);
                });
            });
        });
    };

    Lawn.prototype.logout = function (req, res, user) {
        var sql = "DELETE FROM sessions WHERE user = ? AND token = ?";
        return this.ground.db.query(sql, [user.id, req.sessionID]).then(function () {
            return res.json({ key: 'logged-out' });
        });
    };

    Lawn.prototype.is_configured_for_password_reset = function () {
        return this.config.site && this.config.site.name && this.mail && typeof this.password_reset_template == 'string';
    };

    Lawn.prototype.check_password_reset_configuration = function (req, res, body) {
        return this.is_configured_for_password_reset() ? when.resolve() : when.reject({
            status: 400,
            message: "This site is not configured to support resetting passwords.",
            key: "vineyard-password-not-configured"
        });
    };

    Lawn.prototype.password_reset_request = function (req, res, body) {
        var _this = this;
        return this.check_password_reset_configuration(req, res, body).then(function () {
            return _this.ground.db.query_single("SELECT * FROM users WHERE username = ?", [body.username]);
        }).then(function (user) {
            if (!user) {
                return when.reject({
                    status: 400,
                    message: "There is no user with that username.",
                    key: "vineyard-password-reset-user-not-found"
                });
            }
            if (!user.email) {
                return when.reject({
                    status: 400,
                    message: "An email address is required to reset your password, and your account does not have an email address.",
                    key: "vineyard-password-reset-no-email-address"
                });
            }
            var sql = "SELECT * FROM password_reset_requests" + "\nJOIN users ON users.id = password_reset_requests.id AND users.username = ?" + "\nWHERE password_reset_requests.created > UNIX_TIMESTAMP() - 12 * 60 * 60" + "\nORDER BY used DESC";
            return _this.ground.db.query_single(sql, [body.username]).then(function (row) {
                if (row) {
                    if (row.used) {
                        res.send({
                            message: "Your password was recently reset.  You must wait 12 hours before resetting it again.",
                            key: "vineyard-password-reset-recently"
                        });
                    } else {
                        res.send({
                            message: "An email with a temporary password was recently sent to you.",
                            key: "vineyard-password-reset-already-sent"
                        });
                    }
                } else {
                    return _this.create_password_reset_entry(user.id).then(function (entry) {
                        var email = {
                            title: _this.config.site.name + " Password Reset",
                            content: _this.password_reset_template.replace(/\{name}/g, user.username).replace(/\{password}/g, entry.password)
                        };
                        return _this.invoke('compose-password-reset-email', email).then(function () {
                            return _this.mail.send(user.email, email.title, email.content).then(function () {
                                res.send({
                                    message: "A tempory password was sent to your email.",
                                    key: "vineyard-password-reset-sent"
                                });
                            });
                        });
                    });
                }
                return when.resolve();
            });
        });
    };

    Lawn.prototype.create_password_reset_entry = function (user_id) {
        function generate_password() {
            var range = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
            var result = '';
            for (var i = 0; i < 8; ++i) {
                result += range[Math.floor(Math.random() * range.length)];
            }

            return result;
        }

        var password = generate_password();

        var sql = "INSERT INTO password_reset_requests (`user`, `password`, `created`, `modified`, `used`)" + " VALUES (?, ?, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 0)";
        return this.ground.db.query(sql, [user_id, password]).then(function () {
            return {
                password: password
            };
        });
    };

    Lawn.create_session = function (user, req, ground) {
        var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;

        if (!ip && req.connection.socket)
            ip = req.connection.socket.remoteAddress;

        var session = [
            user.id,
            req.sessionID,
            ip,
            Math.round(new Date().getTime() / 1000)
        ];

        return ground.db.query("REPLACE INTO sessions (user, token, hostname, timestamp) VALUES (?, ?, ?, ?)", session).then(function () {
            return session;
        });
    };

    Lawn.prototype.add_service = function (definition) {
        this.services.push(definition);
    };

    Lawn.prototype.create_service = function (service) {
        var _this = this;
        if (service.http_path) {
            if (service.http_path[0] != '/')
                service.http_path = '/' + service.http_path;

            this.app.post(service.http_path, function (req, res) {
                var user = null;

                when.resolve().then(function () {
                    return _this.get_user_from_session(req.sessionID);
                }).then(function (u) {
                    user = u;
                    return _this.check_service(req.body, user, service.authorization, service.validation);
                }).then(function () {
                    return service.action(req.body, user);
                }).done(function (response) {
                    res.send(response);
                }, function (error) {
                    var response = _this.process_error(error, user);
                    var status = response.status;
                    delete response.status;
                    res.status(status).json(response);
                });
            });
        }
    };

    Lawn.prototype.check_service = function (data, user, authorization, validation) {
        if (authorization != null) {
            var fortress = this.vineyard.bulbs.fortress;
            var access = authorization(user, fortress);
            if (!access)
                throw new Authorization_Error('Unauthorized');
        }

        if (validation) {
            var error = this.vineyard.find_schema_errors(data, validation);
            if (error) {
                var message = null;
                if (error.code == 303) {
                    message = "Unsupported property: " + error.dataPath.substring(1);
                } else {
                    message = error.dataPath == "" ? error.message : error.message + " for " + error.dataPath.substring(1);
                }

                throw new HttpError(message, 400, 'invalid-structure');
            }
        }

        return when.resolve();
    };

    Lawn.prototype.send_http_login_success = function (req, res, user) {
        var query = this.ground.create_query('user');
        query.add_key_filter(user.id);
        query.run_single().then(function (row) {
            res.send({
                token: req.sessionID,
                message: 'Login successful',
                user: Lawn.format_internal_user(row)
            });
        });
    };

    Lawn.prototype.register = function (req, res) {
        var _this = this;
        var body = req.body, username = body.username, email = body.email, password = body.password, phone = body.phone, facebook_token = body.facebook_token, display_name = body[this.config.display_name_key];

        if (typeof username != 'string' || username.length > 32 || !username.match(this.config.valid_username))
            return when.reject(new HttpError('Invalid username.', 400));

        if (email && (!email.match(/\S+@\S+\.\S/) || email.match(/['"]/)))
            return when.reject(new HttpError('Invalid email address.', 400));

        if (typeof password != 'string' || password.length > 32 || !password.match(this.config.valid_password))
            return when.reject(new HttpError('Invalid username.', 400));

        if (typeof display_name != 'string')
            display_name = null;
        else if (!display_name.match(this.config.valid_display_name))
            return when.reject(new HttpError("Invalid " + this.config.display_name_key, 400));

        var register = function (facebook_id) {
            if (typeof facebook_id === "undefined") { facebook_id = undefined; }
            var args = [body.username];
            var sql = "SELECT 'username' as value FROM users WHERE username = ?";
            if (body.email) {
                sql += "\nUNION SELECT 'email' as value FROM users WHERE email = ?";
                args.push(body.email);
            }

            if (facebook_id) {
                sql += "\nUNION SELECT 'facebook_id' as value FROM users WHERE facebook_id = ?";
                args.push(facebook_id);
            }

            return _this.ground.db.query(sql, args).then(function (rows) {
                if (rows.length > 0)
                    return when.reject(new HttpError('That ' + rows[0].value + ' is already taken.', 400));

                var gender = body.gender;
                if (gender !== 'male' && gender !== 'female')
                    gender = null;

                var user = {
                    username: username,
                    email: email,
                    password: body.password,
                    gender: gender,
                    phone: phone,
                    roles: [2],
                    address: body.address,
                    image: body.image
                };
                user[_this.config.display_name_key] = display_name;

                console.log('user', user, facebook_id);
                _this.ground.create_update('user', user).run().then(function (user) {
                    var finished = function () {
                        user.facebook_id = facebook_id;
                        res.send({
                            message: 'User ' + username + ' created successfully.',
                            user: user
                        });
                    };
                    if (facebook_id)
                        return _this.ground.db.query_single("UPDATE users SET facebook_id = ? WHERE id = ?", [facebook_id, user.id]).then(finished);

                    finished();
                });
            });
        };

        if (facebook_token !== undefined) {
            return this.vineyard.bulbs.facebook.get_user_facebook_id(body).then(function (facebook_id) {
                return register(facebook_id);
            });
        } else {
            return register();
        }
    };

    Lawn.prototype.link_facebook_user = function (req, res, user) {
        var _this = this;
        var body = req.body;
        if (body.facebook_token === null || body.facebook_token === '') {
            console.log('connect-fb-user-detach', user);
            delete user.facebook_id;
            return this.ground.db.query_single("UPDATE users SET facebook_id = NULL WHERE id = ?", [user.id]).then(function () {
                res.send({
                    message: 'Your user accont and facebook account are now detached.',
                    user: user
                });
            });
        }
        return this.vineyard.bulbs.facebook.get_user_facebook_id(body).then(function (facebook_id) {
            var args = [body.username];
            var sql = "SELECT 'username' as value, FROM users WHERE username = ?";
            if (body.email) {
                sql += "UNION SELECT 'email' as value FROM users WHERE email = ?";
                args.push(body.email);
            }

            if (facebook_id) {
                sql += "UNION SELECT 'facebook_id' as value FROM users WHERE facebook_id = ?";
                args.push(facebook_id);
            }

            console.log('connect-fb-user', {
                id: user.id,
                facebook_id: facebook_id
            });
            return _this.ground.db.query_single("UPDATE users SET facebook_id = NULL WHERE facebook_id = ?", [facebook_id]).then(function () {
                return _this.ground.db.query_single("UPDATE users SET facebook_id = ? WHERE id = ?", [facebook_id, user.id]);
            }).then(function () {
                user.facebook_id = facebook_id;
                res.send({
                    message: 'Your user accont is now attached to your facebook account.',
                    user: user
                });
            });
        });
    };

    Lawn.request = function (options, data, secure) {
        if (typeof data === "undefined") { data = null; }
        if (typeof secure === "undefined") { secure = false; }
        var def = when.defer();
        var http = require(secure ? 'https' : 'http');

        var req = http.request(options, function (res) {
            res.setEncoding('utf8');
            if (res.statusCode != '200') {
                res.on('data', function (chunk) {
                    console.log('client received an error:', res.statusCode, chunk);
                    def.reject();
                });
            } else {
                res.on('data', function (data) {
                    if (res.headers['content-type'] && (res.headers['content-type'].indexOf('json') > -1 || res.headers['content-type'].indexOf('javascript') > -1))
                        res.content = JSON.parse(data);
                    else
                        res.content = data;

                    def.resolve(res);
                });
            }
        });

        if (data)
            req.write(JSON.stringify(data));

        req.end();

        req.on('error', function (e) {
            console.log('problem with request: ' + e.message);
            def.reject();
        });

        return def.promise;
    };

    Lawn.prototype.login = function (data, socket, callback) {
        var _this = this;
        console.log('message2', data);
        if (!data.token) {
            socket.emit('error', { message: 'Missing token.' });
        }

        var query = this.ground.create_query('session');
        query.add_key_filter(data.token);

        this.get_user_from_session(data.token).then(function (user) {
            _this.initialize_session(socket, user);
            console.log('user', user);
            if (callback) {
                console.log('login callback called');
                callback(user);
            }
        }, function (error) {
            console.log('error', error.message, error.stack);

            socket.emit('socket login error', {
                'message': error.status == 500 || !error.message ? 'Error getting session.' : error.message
            });
        }).done();
    };

    Lawn.prototype.on_connection = function (socket) {
        var _this = this;
        console.log('connection attempted');
        socket.on('login', function (data, callback) {
            return _this.login(data, socket, callback);
        });

        socket.emit('connection');
        return socket.on('disconnect', function () {
            var data, user;
            _this.debug('***detected disconnect');
            user = socket.user;
            if (user)
                delete _this.instance_user_sockets[user.id][socket.id];

            delete _this.instance_sockets[socket.id];
            if (user && !_this.user_is_online(user.id)) {
                _this.debug(user.id);
                data = user;
                if (_this.ground.db.active)
                    return _this.ground.db.query('UPDATE users SET online = 0 WHERE id = ' + user.id);
            }

            return when.resolve();
        });
    };

    Lawn.process_public_http = function (req, res, action) {
        action(req, res).done(function () {
        }, function (error) {
            error = error || {};
            var status = error.status || 500;
            var message = status == 500 ? 'Server Error' : error.message;
            console.log('public http error:', status || 500, error.message, error.stack);
            res.status(status || 500).json({ message: message });
        });
    };

    Lawn.prototype.on_socket = function (socket, event, user, action) {
        var _this = this;
        socket.on(event, function (request, callback) {
            callback = callback || function () {
            };
            try  {
                var promise = action(request);
                if (promise && typeof promise.done == 'function') {
                    promise.done(function (response) {
                        response = response || {};
                        response.status = response.status || 200;
                        callback(response);
                    }, function (error) {
                        return callback(_this.process_error(error, user));
                    });
                } else {
                    callback({ status: 200 });
                }
            } catch (err) {
                callback(_this.process_error(err, user));
            }
        });
    };

    Lawn.listen_public_http = function (app, path, action, method) {
        if (typeof method === "undefined") { method = 'post'; }
        app[method](path, function (req, res) {
            return Lawn.process_public_http(req, res, action);
        });
    };

    Lawn.prototype.listen_public_http = function (path, action, method) {
        if (typeof method === "undefined") { method = 'post'; }
        this.app[method](path, function (req, res) {
            return Lawn.process_public_http(req, res, action);
        });
    };

    Lawn.prototype.process_error = function (error, user) {
        var status = error.status || 500;
        var message = status == 500 ? 'Server Error' : error.message;

        var response = {
            status: status,
            message: message,
            key: error.key || 'unknown'
        };

        var fortress = this.vineyard.bulbs.fortress;
        if (user && fortress && fortress.user_has_role(user, 'dev')) {
            response.message = error.message || "Server Error";
            response['stack'] = error.stack;
            response['details'] = error.details;
        }

        if (this.config.log_authorization_errors !== false || status != 403)
            console.log('service error:', status, error.message, error.stack, error.key);

        return response;
    };

    Lawn.prototype.process_user_http = function (req, res, action) {
        var _this = this;
        var user = null, send_error = function (error) {
            var response = _this.process_error(error, user);
            var status = response.status;
            delete response.status;
            res.status(status).json(response);
        };
        try  {
            this.get_user_from_session(req.sessionID).then(function (u) {
                user = u;
                return action(req, res, user);
            }).done(function () {
            }, send_error);
        } catch (error) {
            send_error(error);
        }
    };

    Lawn.prototype.listen_user_http = function (path, action, method) {
        if (typeof method === "undefined") { method = 'post'; }
        var _this = this;
        this.app[method](path, function (req, res) {
            _this.process_user_http(req, res, action);
        });
    };

    Lawn.prototype.start_sockets = function (port) {
        if (typeof port === "undefined") { port = null; }
        var _this = this;
        var socket_io = require('socket.io');
        port = port || this.config.ports.websocket;
        console.log('Starting Socket.IO on port ' + port);

        var io = this.io = socket_io.listen(port);
        io.set('log level', 1);
        io.server.on('error', function (e) {
            if (e.code == 'EADDRINUSE') {
                console.log('Port in use: ' + port + '.');
                _this.io = null;
            }
        });

        io.configure(function () {
            return io.set('authorization', Lawn.authorization);
        });

        io.sockets.on('connection', function (socket) {
            return _this.on_connection(socket);
        });

        if (this.config.use_redis) {
            console.log('using redis');
            var RedisStore = require('socket.io/lib/stores/redis'), redis = require("socket.io/node_modules/redis"), pub = redis.createClient(), sub = redis.createClient(), client = redis.createClient();

            io.set('store', new RedisStore({
                redisPub: pub, redisSub: sub, redisClient: client
            }));
        }
    };

    Lawn.prototype.file_download = function (req, res, user) {
        var _this = this;
        var guid = req.params.guid;
        var ext = req.params.ext;
        if (!guid.match(/[\w\-]+/) || !ext.match(/\w+/))
            throw new HttpError('Invalid File Name', 400);

        var path = require('path');
        var filepath = path.join(this.vineyard.root_path, this.config.file_path || 'files', guid + '.' + ext);
        console.log(filepath);
        return Lawn.file_exists(filepath).then(function (exists) {
            if (!exists)
                throw new HttpError('File Not Found', 404);

            var query = _this.ground.create_query('file');
            query.add_key_filter(req.params.guid);
            var fortress = _this.vineyard.bulbs.fortress;

            fortress.query_access(user, query).then(function (result) {
                if (result.access)
                    res.sendfile(filepath);
                else
                    throw new HttpError('Access Denied', 403);
            });
        });
    };

    Lawn.file_exists = function (filepath) {
        var fs = require('fs'), def = when.defer();
        fs.exists(filepath, function (exists) {
            def.resolve(exists);
        });
        return def.promise;
    };

    Lawn.prototype.start_http = function (port) {
        var _this = this;
        if (!port)
            return;

        var express = require('express');
        var app = this.app = express();

        var parser = require('body-parser');
        app.use(parser.json());
        app.use(require('cookie-parser')());

        var session = require('express-session');
        if (typeof this.config.mysql_session_store == 'object') {
            var MySQL_Session_Store = require('express-mysql-session');
            var storage_config = this.config.mysql_session_store;

            console.log('using mysql sessions store: ', storage_config.db);

            app.use(session({
                key: storage_config.key,
                secret: storage_config.secret,
                resave: true,
                saveUninitialized: true,
                store: new MySQL_Session_Store(storage_config.db)
            }));
        } else {
            if (!this.config.cookie_secret)
                throw new Error('lawn.cookie_secret must be set!');

            app.use(session({
                secret: this.config.cookie_secret, resave: true,
                saveUninitialized: true
            }));
        }

        if (this.config.allow_cors === true) {
            app.use(require('cors')());
            console.log('Using CORS');
        }

        if (typeof this.config.log_file === 'string') {
            var fs = require('fs');
            var log_file = fs.createWriteStream(this.config.log_file, { flags: 'a' });
            app.use(express.logger({ stream: log_file }));
        }

        this.listen_public_http('/vineyard/login', function (req, res) {
            return _this.http_login(req, res, req.body);
        });
        this.listen_public_http('/vineyard/login', function (req, res) {
            return _this.http_login(req, res, req.query);
        }, 'get');
        this.listen_user_http('/vineyard/logout', function (req, res, user) {
            return _this.logout(req, res, user);
        });
        this.listen_user_http('/vineyard/logout', function (req, res, user) {
            return _this.logout(req, res, user);
        }, 'get');

        for (var i in this.services) {
            this.create_service(this.services[i]);
        }

        this.listen_public_http('/vineyard/password-reset', function (req, res) {
            return _this.password_reset_request(req, res, req.body);
        });
        this.listen_user_http('/vineyard/current-user', function (req, res, user) {
            res.send({
                status: 200,
                user: Lawn.format_public_user(user)
            });
            return when.resolve();
        }, 'get');

        this.listen_user_http('/vineyard/upload', function (req, res, user) {
            console.log('files', req.files);
            console.log('req.body', req.body);
            var info = JSON.parse(req.body.info);
            var file = req.files.file;
            var guid = info.guid;
            if (!guid)
                throw new HttpError('guid is empty.', 400);

            if (!guid.match(/[\w\-]+/))
                throw new HttpError('Invalid guid.', 400);

            var path = require('path');
            var ext = path.extname(file.originalFilename) || '';
            var filename = guid + ext;
            var filepath = (_this.config.file_path || 'files') + '/' + filename;
            var fs = require('fs');
            fs.rename(file.path, filepath);

            return _this.ground.update_object('file', {
                guid: guid,
                name: filename,
                path: file.path,
                size: file.size,
                extension: ext.substring(1),
                status: 1
            }, user).then(function (object) {
                res.send({ file: object });
                _this.invoke('file.uploaded', object);
            });
        });

        this.listen_user_http('/file/:guid.:ext', function (req, res, user) {
            return _this.file_download(req, res, user);
        }, 'get');
        this.listen_user_http('/vineyard/facebook/link', function (req, res, user) {
            return _this.link_facebook_user(req, res, user);
        }, 'post');
        this.listen_user_http('/vineyard/schema', function (req, res, user) {
            return _this.get_schema(req, res, user);
        }, 'get');

        app.use(function (err, req, res, next) {
            console.log('e');
            console.error(err.stack);
            if (err && err.name == 'SyntaxError') {
                res.status(400).json({
                    message: 'Invalid JSON',
                    key: 'invalid-json'
                });
            }
            next(err);
        });

        port = port || this.config.ports.http;
        console.log('HTTP listening on port ' + port + '.');

        this.invoke('http.start', app, this);
        this.http = app.listen(port);
    };

    Lawn.prototype.stop = function () {
        console.log('Stopping Lawn');

        if (this.io && this.io.server) {
            console.log('Stopping Socket.IO');
            var clients = this.io.sockets.clients();
            for (var i in clients) {
                clients[i].disconnect();
            }
            this.io.server.close();
            this.io = null;
        }

        if (this.redis_client) {
            this.redis_client.quit();
            this.redis_client = null;
        }

        if (this.http) {
            console.log('Closing HTTP.');
            this.http.close();
            this.http = null;
            this.app = null;
        }

        console.log('Lawn is stopped.');
    };

    Lawn.prototype.user_is_online = function (id) {
        if (!this.io)
            return false;

        var room = this.io.sockets.clients(id);
        return room && room.length > 0;
    };
    Lawn.public_user_properties = ['id', 'name', 'username', 'email'];
    Lawn.internal_user_properties = Lawn.public_user_properties.concat(['roles']);
    return Lawn;
})(Vineyard.Bulb);

var Lawn;
(function (Lawn) {
    Lawn.HttpError;

    var Facebook = (function (_super) {
        __extends(Facebook, _super);
        function Facebook() {
            _super.apply(this, arguments);
        }
        Facebook.prototype.grow = function () {
            this.lawn = this.vineyard.bulbs.lawn;
        };

        Facebook.prototype.create_user = function (facebook_id, source) {
            var _this = this;
            var user = {
                username: source.username,
                email: source.email,
                gender: source.gender,
                facebook_id: facebook_id
            };
            user[this.lawn.config.display_name_key] = source.name;

            console.log('user', user);
            return this.ground.create_update('user', user).run().then(function (user) {
                var result = {
                    id: user.id,
                    username: user.username
                };
                result[_this.lawn.config.display_name_key] = user.name;
                return result;
            });
        };

        Facebook.prototype.login = function (req, res, body) {
            var _this = this;
            console.log('facebook-login', body);

            return this.get_user(body).then(function (user) {
                return Lawn.create_session(user, req, _this.ground).then(function () {
                    return _this.vineyard.bulbs.lawn.send_http_login_success(req, res, user);
                });
            });
        };

        Facebook.prototype.get_user = function (body) {
            var _this = this;
            return this.get_user_facebook_id(body).then(function (facebook_id) {
                console.log('fb-user', facebook_id);
                if (!facebook_id) {
                    return when.resolve(new Lawn.HttpError('Invalid facebook login info.', 400));
                }

                return _this.ground.db.query_single("SELECT id, username FROM users WHERE facebook_id = ?", [facebook_id]).then(function (user) {
                    if (user)
                        return user;

                    throw new Lawn.HttpError('That Facebook user id is not yet connected to an account.  Redirect to registration.', 300);
                });
            });
        };

        Facebook.prototype.get_user_facebook_id = function (body) {
            if (typeof body.facebook_token != 'string' && typeof body.facebook_token != 'number')
                throw new Lawn.HttpError('Requires either valid facebook user id or email address.', 400);

            var options = {
                host: 'graph.facebook.com',
                path: '/oauth/access_token?' + 'client_id=' + this.config['app'].id + '&client_secret=' + this.config['app'].secret + '&grant_type=client_credentials',
                method: 'GET'
            };

            return Lawn.request(options, null, true).then(function (response) {
                var url = require('url');
                var info = url.parse('temp.com?' + response.content, true);
                var access_token = info.query.access_token;

                var post = {
                    host: 'graph.facebook.com',
                    path: '/debug_token?' + 'input_token=' + body.facebook_token + '&access_token=' + access_token,
                    method: 'GET'
                };

                return Lawn.request(post, null, true);
            }).then(function (response) {
                console.log('facebook-check', response.content);
                return response.content.data.user_id;
            });
        };
        return Facebook;
    })(Vineyard.Bulb);
    Lawn.Facebook = Facebook;

    var Songbird = (function (_super) {
        __extends(Songbird, _super);
        function Songbird() {
            _super.apply(this, arguments);
            this.fallback_bulbs = [];
        }
        Songbird.prototype.grow = function () {
            var _this = this;
            this.lawn = this.vineyard.bulbs.lawn;
            this.listen(this.lawn, 'socket.add', function (socket, user) {
                return _this.initialize_socket(socket, user);
            });
            if (this.config.template_file) {
                var fs = require('fs');
                var json = fs.readFileSync(this.config.template_file, 'ascii');
                this.templates = JSON.parse(json);
            }
        };

        Songbird.prototype.initialize_socket = function (socket, user) {
            var _this = this;
            this.lawn.on_socket(socket, 'notification/received', user, function (request) {
                return _this.notification_receieved(user, request);
            });

            this.lawn.on_socket(socket, 'notification/received', user, function (request) {
                return _this.send_pending_notifications(user);
            });
        };

        Songbird.prototype.add_fallback = function (fallback) {
            this.fallback_bulbs.push(fallback);
        };

        Songbird.prototype.format_message = function (name, data) {
            if (!this.templates)
                return name;

            if (!this.templates[name])
                throw new Error("Could not find a message template for " + name + ".");

            return this.templates[name].join("");
        };

        Songbird.prototype.notify = function (users, name, data, trellis_name, store) {
            if (typeof store === "undefined") { store = true; }
            var _this = this;
            var ground = this.lawn.ground;
            var users = users.map(function (x) {
                return typeof x == 'object' ? x.id : x;
            });
            var message;

            if (!store || !trellis_name) {
                if (!this.lawn.io)
                    return when.resolve();

                var promises = [];
                for (var i = 0; i < users.length; ++i) {
                    var id = users[i];
                    console.log('sending-message', name, id, data);
                    var online = this.lawn.user_is_online(id);
                    console.log('online', online);
                    this.lawn.io.sockets.in('user/' + id).emit(name, data);
                    if (!online) {
                        console.log('fallback count', this.fallback_bulbs.length);
                        message = this.format_message(name, data);
                        for (var x = 0; x < this.fallback_bulbs.length; ++x) {
                            promises.push(this.fallback_bulbs[x].send({ id: id }, message, data, 0));
                        }
                    }
                }
                return when.all(promises);
            }

            data.event = name;
            return ground.create_update(trellis_name, data, this.lawn.config.admin).run().then(function (notification) {
                var promises = users.map(function (id) {
                    console.log('sending-message', name, id, data);

                    var online = _this.lawn.user_is_online(id);

                    return ground.create_update('notification_target', {
                        notification: notification.id,
                        recipient: id,
                        received: online
                    }, _this.lawn.config.admin).run().then(function () {
                        _this.lawn.io.sockets.in('user/' + id).emit(name, data);
                        if (online)
                            return when.resolve();

                        message = _this.format_message(name, data);
                        return when.all(_this.fallback_bulbs.map(function (b) {
                            return b.send({ id: id }, message, data, 0);
                        }));
                    });
                });

                return when.all(promises);
            });
        };

        Songbird.prototype.notification_receieved = function (user, request) {
            var ground = this.lawn.ground;
            var query = ground.create_query('notification_target');
            query.add_filter('recipient', user);
            query.add_filter('notification', request.notification);
            return query.run_single().then(function (object) {
                if (!object)
                    throw new Lawn.HttpError('Could not find a notification with that id and target user.', 400);

                if (object.received)
                    throw new Lawn.HttpError('That notification was already marked as received.', 400);

                return ground.update_object('notification_target', {
                    id: object.id,
                    received: true
                }).then(function (object) {
                    return { message: "Notification is now marked as received." };
                });
            });
        };

        Songbird.prototype.send_pending_notifications = function (user) {
            var _this = this;
            var ground = this.lawn.ground;
            var query = ground.create_query('notification_target');
            query.add_filter('recipient', user);
            query.add_filter('received', false);
            query.run().done(function (objects) {
                for (var i = 0; i < objects.length; ++i) {
                    var notification = objects[i].notification;
                    _this.lawn.io.sockets.in('user/' + user.id).emit(notification.event, notification.data);
                }
            });
        };
        return Songbird;
    })(Vineyard.Bulb);
    Lawn.Songbird = Songbird;

    var Mail = (function () {
        function Mail(config) {
            this.config = config;
            var nodemailer = require('nodemailer');
            var ses_transport = require('nodemailer-ses-transport');
            this.transporter = nodemailer.createTransport(ses_transport(config));
        }
        Mail.prototype.send = function (to, subject, text) {
            var def = when.defer();
            console.log(this.config.address);
            this.transporter.sendMail({
                from: this.config.address,
                to: to,
                subject: subject,
                html: text
            }, function (error, info) {
                if (error) {
                    console.log('error', error);
                    def.reject(error);
                } else {
                    def.resolve(info);
                    console.log('info', info);
                }
            });

            return def.promise;
        };
        return Mail;
    })();
    Lawn.Mail = Mail;
})(Lawn || (Lawn = {}));
Lawn.HttpError = common.HttpError;

module.exports = Lawn;
//# sourceMappingURL=lawn.js.map
