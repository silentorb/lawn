/**
* User: Chris Johnson
* Date: 11/15/2014
*/
/// <reference path="references.ts"/>
var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
var when = require('when')
var MetaHub = require('vineyard-metahub')
var Ground = require('vineyard-ground')
var Vineyard = require('vineyard')
var HttpError = (function () {
    function HttpError(message, status, key) {
        if (typeof status === "undefined") { status = 500; }
        if (typeof key === "undefined") { key = undefined; }
        this.name = "HttpError";
        this.message = message;
        this.status = status;
        this.key = key;
    }
    return HttpError;
})();

var Authorization_Error = (function (_super) {
    __extends(Authorization_Error, _super);
    function Authorization_Error(message, user) {
        _super.call(this, message, user.username == 'anonymous' ? 401 : 403);
    }
    return Authorization_Error;
})(HttpError);

function is_authenticated(user, fortress) {
    return user && typeof user.id == 'number' && user.username != 'anonymous';
}

function is_admin(user, fortress) {
    return fortress.user_has_role(user, 'admin');
}
/**
* User: Chris Johnson
* Date: 11/15/2014
*/
/// <reference path="references.ts"/>
var Gardener = (function () {
    function Gardener() {
    }
    Gardener.set_config = function (data, lawn) {
        if (data.socket) {
            if (typeof data.socket.log == 'boolean') {
                lawn.io.set('log level', data.socket.log ? 3 : 0);
                console.log("Gardener turned socket logging " + (data.socket.log ? 'on' : 'off'));
            }
        }
        return when.resolve({
            message: 'Done',
            key: 'success'
        });
    };

    Gardener.grow = function (lawn) {
        var Path = require('path');
        lawn.vineyard.load_json_schema('gardener-config', Path.resolve(__dirname, './validation/gardener-config.json'));
        lawn.add_service({
            http_path: 'vineyard/gardener/config',
            socket_path: 'gardener/config',
            authorization: is_admin,
            validation: 'gardener-config',
            action: function (data) {
                return function (data) {
                    return Gardener.set_config(data, lawn);
                };
            }
        });
        //lawn.create_user_service('vineyard/gardener/config', 'gardener/config',
        //  is_admin, '../validation/gardener-config.json', (data)=> set_config(data, lawn))
    };
    return Gardener;
})();
/// <reference path="references.ts"/>
var Irrigation = (function () {
    function Irrigation() {
    }
    Irrigation.query = function (request, user, lawn) {
        var ground = lawn.ground, vineyard = lawn.vineyard;
        var Fortress = require('vineyard-fortress');
        if (vineyard.bulbs['lawn'].config.require_version === true && !request.version)
            throw new HttpError('The request must have a version property.', 400, 'version-required');

        if (!request)
            throw new HttpError('Empty request', 400);

        if (!ground.trellises[request.trellis])
            throw new HttpError('Invalid trellis: ' + request.trellis + '.', 400, 'invalid-trellis');

        var trellis = ground.sanitize_trellis_argument(request.trellis);
        var query = new Ground.Query_Builder(trellis);

        Irrigation.inject_user(request, user);

        query.extend(request);

        var fortress = vineyard.bulbs.fortress;
        return fortress.query_access(user, query).then(function (result) {
            //console.log('fortress', result)
            if (result.is_allowed) {
                result.secure_query(query);
                return Irrigation.run_query(query, user, vineyard, request);
            } else {
                throw new Authorization_Error(result.get_message(), user);
            }
        });
    };

    Irrigation.inject_user = function (query, user) {
        if (query.filters) {
            for (var i = 0; i < query.filters.length; ++i) {
                var filter = query.filters[i];
                if (filter.type == 'parameter' && filter.value == 'user') {
                    filter.value = user.id;
                }
            }
        }
    };

    Irrigation.run_query = function (query, user, vineyard, request) {
        var lawn = vineyard.bulbs['lawn'];
        var query_result = { query_count: 0, user: user };
        var fortress = vineyard.bulbs.fortress;
        if (request.return_sql === true && (!fortress || fortress.user_has_role(user, 'dev')))
            query_result.return_sql = true;

        var start = Date.now();
        return query.run(user, query_result).then(function (result) {
            result.query_stats.duration = Math.abs(Date.now() - start);
            if (result.sql && !vineyard.ground.log_queries)
                console.log('\nservice-query:', "\n" + result.sql);

            if (result.total === undefined)
                result.total = result.objects.length;

            if (lawn.config.log_queries === true) {
                var sql = "INSERT INTO query_log (user, trellis, timestamp, request, duration, query_count, object_count, version)" + " VALUES (?, ?, UNIX_TIMESTAMP(), ?, ?, ?, ?, ?)";

                // This may cause some problems with the automated tests,
                // but the response does not wait for this log to be stored.
                // I'm doing it this way because the whole point of this log is performance timing
                // and I don't want it to bloat the perceived external request time.
                query.ground.db.query(sql, [
                    user.id,
                    query.trellis.name,
                    JSON.stringify(request),
                    result.query_stats.duration,
                    result.query_stats.count,
                    result.objects.length,
                    request.version || lawn.config.default_version || "?"
                ]);
            }
            return result;
        });
    };

    Irrigation.update2 = function (request, user, lawn) {
        var ground = lawn.ground, vineyard = lawn.vineyard;
        if (vineyard.bulbs['lawn'].config.require_version === true && !request.version)
            throw new HttpError('The request must have a version property.', 400, 'version-required');

        var updates = request.objects.map(function (object) {
            return ground.create_update(object.trellis, object, user);
        });

        var fortress = vineyard.bulbs.fortress;
        return fortress.update_access(user, updates).then(function (result) {
            if (result.is_allowed) {
                var update_promises = updates.map(function (update) {
                    return update.run();
                });
                return when.all(update_promises).then(function (objects) {
                    return {
                        objects: objects
                    };
                });
            } else {
                throw new Authorization_Error(result.get_message(), user);
            }
        });
    };

    Irrigation.grow = function (lawn) {
        lawn.vineyard.add_json_schema('ground-query', lawn.ground.query_schema);
        lawn.vineyard.add_json_schema('ground-update', lawn.ground.update_schema);
        lawn.add_service({
            http_path: 'vineyard/query',
            socket_path: 'query',
            //authorization: is_authenticated,
            validation: 'ground-query',
            action: function (data, user) {
                return Irrigation.query(data, user, lawn);
            }
        });

        lawn.add_service({
            http_path: 'vineyard/update',
            socket_path: 'update',
            //authorization: is_authenticated,
            validation: 'ground-update',
            action: function (data, user) {
                return Irrigation.update2(data, user, lawn);
            }
        });
    };
    return Irrigation;
})();
/// <reference path="references.ts"/>
/// <reference path="mysql-session.ts"/>
var mysql_session = require('./lib/mysql-session');

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
    Lawn.prototype.till_ground = function (ground_config) {
        var display_name_key = this.config.display_name_key || 'display_name';
        if (display_name_key == 'display_name') {
            this.vineyard.add_schema("node_modules/vineyard-lawn/schema/user-new.json");
        } else {
            this.vineyard.add_schema("node_modules/vineyard-lawn/schema/user-old.json");
        }

        this.vineyard.add_schema("node_modules/vineyard-lawn/schema/common.json");
        this.vineyard.add_schema("node_modules/vineyard-lawn/schema/utility.json");
    };

    Lawn.prototype.grow = function () {
        var _this = this;
        var ground = this.ground;

        // Lawn requires vineyard-user whether or not it was included in the site config files.
        var user_bulb = this.vineyard.bulbs['user'];
        if (!user_bulb) {
            user_bulb = this.vineyard.load_bulb('user', {
                path: require('path').resolve(__dirname, 'node_modules/vineyard-user')
            });
        }

        this.config.display_name_key = this.config.display_name_key || 'display_name';

        if (this.config.log_updates) {
            this.listen(ground, '*.update', function (seed, update) {
                // Don't want an infinite loop
                if (update.trellis.name == 'update_log')
                    return when.resolve();

                var sql = "INSERT INTO update_logs (`trellis`, `user`, `data`, `created`, `modified`)\n" + "VALUES(?, ?, ?, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())";

                when.resolve().then(function () {
                    return _this.ground.db.query(sql, [
                        update.trellis.name,
                        update.user ? update.user.id : 0,
                        JSON.stringify(seed)
                    ]);
                }).done(function () {
                }, function (error) {
                    console.error('update_log error', error);
                });

                return when.resolve();
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

        this.config['valid_display_name'] = typeof this.config.valid_display_name == 'string' ? new RegExp(this.config.valid_display_name) : /^[A-Za-z\-_0-9 ]+$/;

        Irrigation.grow(this);

        Gardener.grow(this);
    };

    Lawn.authorization = function (handshakeData, callback) {
        return callback(null, true);
    };

    Lawn.prototype.emit_to_users = function (users, name, data) {
        throw new Error("Lawn.emit_to_users was removed.");
        //return this.vineyard.bulbs.songbird.notify(users, name, data)
    };

    Lawn.prototype.notify = function (user, name, data, trellis_name) {
        console.warn("Lawn.notify() is deprecated.  Use Songbird.notify() instead.");
        return this.vineyard.bulbs.songbird.notify(user, name, data, trellis_name);
    };

    Lawn.prototype.get_user_sockets = function (id) {
        return MetaHub.map_to_array(this.instance_user_sockets[id], function (x) {
            return x;
        }) || [];
    };

    Lawn.prototype.initialize_session = function (socket, user) {
        socket.user = user;
        this.instance_sockets[socket.id] = socket;
        this.instance_user_sockets[user.id] = this.instance_user_sockets[user.id] || [];
        this.instance_user_sockets[user.id][socket.id] = socket;
        this.ground.db.query('UPDATE users SET online = 1 WHERE id = ' + user.id);

        socket.join('user/' + user.id);

        //socket.on('query', (request, callback)=>
        //    Irrigation.process('query', request, user, this.vineyard, socket, callback)
        //)
        //
        //socket.on('update', (request, callback)=>
        //    Irrigation.process('update', request, user, this.vineyard, socket, callback)
        //)
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

        for (var i in this.services) {
            var service = this.services[i];
            if (service.socket_path)
                this.create_socket_service(socket, user, service);
        }

        user.online = true;
        this.invoke('socket.add', socket, user);

        console.log(process.pid, 'Logged in: ' + user.id);
    };

    // Attach user online status to any queried users
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
            if (_this.config.ports.http)
                _this.start_http(_this.config.ports.http);
            if (_this.config.ports.websocket)
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
        var result = MetaHub.extend({}, user);
        delete result.password;
        return result;
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
        return query.run_single(null).then(function (user) {
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

        return query.run_single(null).then(function (session) {
            //console.log('session', session)
            var user = !session || session.token === 0 || typeof session.user !== 'object' || !session.user.id ? { id: 2, username: 'anonymous', roles: [{ id: 3, name: 'anonymous' }] } : session.user;

            return Lawn.format_internal_user(user);
        });
    };

    Lawn.prototype.http_login = function (req, res, body) {
        var _this = this;
        if (typeof body.facebook_token === 'string')
            return this.vineyard.bulbs.facebook.login(req, res, body);

        var user_bulb = this.vineyard.bulbs['user'];

        var username = body.username || body.name;
        var password = user_bulb.prepare_password(body.password || body.pass);

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
                    throw new Authorization_Error('This account has been disabled.', user);

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
                throw new Authorization_Error('This account has been disabled.', user);

            if (user.status === 2)
                throw new Authorization_Error('This account is awaiting email verification.', user);

            var roles_sql = 'SELECT * FROM roles' + '\nJOIN roles_users ON roles.id = roles_users.role' + '\nWHERE user = ?';
            return _this.ground.db.query(roles_sql, [user.id]).then(function (roles) {
                user.roles = roles;
                return _this.invoke('user.login', user, body);
            }).then(function () {
                return Lawn.create_session(user, req, _this.ground).then(function () {
                    return _this.send_http_login_success(req, res, user, body);
                });
            });
        });
    };

    Lawn.prototype.logout = function (req, res, user) {
        console.log('Deleting session:', req.sessionID);
        req.session.destroy();
        res.json({ key: 'logged-out' });
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
        var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;

        req.session.user = user.id;

        if (!ip && req.connection.socket)
            ip = req.connection.socket.remoteAddress;

        //var session = [
        //	user.id,
        //	req.sessionID,
        //	ip,
        //	Math.round(new Date().getTime() / 1000)
        //]
        return when.resolve();
        //console.log('session', req.session, req.sessionID, user)
        //var sql = "UPDATE `sessions` SET user = ?, ip = ? WHERE token = ?"
        //return ground.db.query(sql, [ user.id, ip, req.sessionID ])
    };

    Lawn.prototype.add_service = function (definition) {
        this.services.push(definition);
    };

    Lawn.prototype.create_service = function (service) {
        var _this = this;
        var http_path = service.http_path[0] != '/' ? '/' + service.http_path : service.http_path;

        this.app.post(http_path, function (req, res) {
            var user = null;

            // Start with a promise so all possible errors (short of one inside when.js) are
            // handled through promise rejections.  Otherwise we would need a try/catch here
            // and redundant error handling.
            when.resolve().then(function () {
                return _this.get_user_from_session(req.sessionID);
            }).then(function (u) {
                user = u;
                return _this.run_service(service, req.body, user, req);
            }).done(function (response) {
                res.send(response);
            }, function (error) {
                var response = _this.process_error(error, user);
                var status = response.status;
                delete response.status;
                res.status(status).json(response);
            });
        });
    };

    Lawn.prototype.run_service = function (service, body, user, req) {
        var _this = this;
        var pipeline = require('when/pipeline');
        return pipeline([
            function () {
                return _this.check_service(body, user, service.authorization, service.validation);
            },
            function () {
                return service.action(body, user, req);
            }
        ]);
    };

    Lawn.prototype.create_socket_service = function (socket, user, service) {
        var _this = this;
        socket.on(service.socket_path, function (body, callback) {
            return _this.run_service(service, body, user, null).done(function (response) {
                if (callback)
                    callback(response);
            }, function (error) {
                error = error || {};
                console.error('socket error with path ' + service.socket_path + ':', error.message, error.status, error.stack);
                console.error(JSON.stringify(body));
                var status = error.status || 500;

                var response = {
                    status: status,
                    request: body,
                    message: status == 500 ? "Server Error" : error.message,
                    key: error.key || 'unknown'
                };

                socket.emit('error', response);
            });
        });
    };

    Lawn.prototype.check_service = function (data, user, authorization, validation) {
        if (authorization != null) {
            var fortress = this.vineyard.bulbs.fortress;
            var access = authorization(user, fortress);
            if (!access)
                throw new Authorization_Error('Unauthorized', user);
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

    Lawn.prototype.send_http_login_success = function (req, res, user, query_arguments) {
        var _this = this;
        if (typeof query_arguments === "undefined") { query_arguments = null; }
        var query = this.ground.create_query('user');
        query.add_key_filter(user.id);
        var run_query = function () {
            return query.run_single(user).then(function (row) {
                res.send({
                    token: req.sessionID,
                    message: 'Login successful',
                    user: Lawn.format_internal_user(row)
                });
                console.log('sent-login-success', user.username);
            });
        };

        if (query_arguments && (query_arguments.properties || query_arguments.expansions)) {
            if (query_arguments.properties)
                query.add_properties(query_arguments.properties);

            if (MetaHub.is_array(query_arguments.expansions))
                query.add_expansions(query_arguments.expansions);

            var fortress = this.vineyard.bulbs.fortress;
            return fortress.query_access(user, query).then(function (result) {
                if (result.is_allowed) {
                    result.secure_query(query);
                    return run_query();
                } else {
                    var sql = "DELETE FROM sessions WHERE user = ? AND token = ?";
                    return _this.ground.db.query(sql, [user.id, req.sessionID]).then(function () {
                        throw new Authorization_Error(result.get_message(), user);
                    });
                }
            });
        } else {
            return run_query();
        }
    };

    Lawn.prototype.register = function (req, res) {
        var _this = this;
        var body = req.body, username = body.username, email = body.email, password = body.password, phone = body.phone, facebook_token = body.facebook_token, display_name = body[this.config.display_name_key];

        console.log('register', body);

        if (typeof username != 'string' || username.length > 32 || !username.match(this.config.valid_username))
            return when.reject(new HttpError('Invalid username.', 400));

        if (email && (!email.match(/\S+@\S+\.\S/) || email.match(/['"]/)))
            return when.reject(new HttpError('Invalid email address.', 400));

        if (!facebook_token) {
            if (typeof password != 'string' || password.length > 32 || !password.match(this.config.valid_password))
                return when.reject(new HttpError('Invalid password.', 400));
        }

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

                var user = {};
                var trellis = _this.ground.trellises['user'];
                var properties = trellis.get_all_properties();
                var embedded_objects = [];
                for (var i in properties) {
                    var property = properties[i];
                    console.log(property.name, property == trellis.primary_key || property.other_trellis != null, body[property.name]);
                    if (property == trellis.primary_key)
                        continue;

                    if (body[property.name] !== undefined && typeof body[property.name] !== 'object')
                        user[property.name] = body[property.name];
                    else if (typeof body[property.name] === 'object')
                        embedded_objects.push(property);
                }
                user['roles'] = [2];

                console.log('user', user, facebook_id);
                _this.ground.create_update('user', user).run().then(function (user) {
                    var promises = [];
                    if (embedded_objects.length > 0) {
                        var seed = {
                            id: user.id
                        };
                        for (var i in embedded_objects) {
                            var property = embedded_objects[i];
                            seed[property.name] = body[property.name];
                        }
                        promises.push(function () {
                            return _this.ground.update_object('user', seed, user);
                        });
                    }

                    if (facebook_id)
                        promises.push(function () {
                            return _this.ground.db.query_single("UPDATE users SET facebook_id = ? WHERE id = ?", [facebook_id, user.id]);
                        });

                    var sequence = require('when/sequence');
                    return sequence(promises).then(function () {
                        user.facebook_id = facebook_id;
                        res.send({
                            message: 'User ' + username + ' created successfully.',
                            user: user
                        });
                    });
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
            //      if (!user.facebook_id) {
            //        res.send({
            //          message: "Your account is already not linked to a facebook account.",
            //          user: user
            //        });
            //        return when.resolve()
            //      }
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

            //        return this.ground.db.query_single("SELECT id, name FROM users WHERE facebook_id = ?", [facebook_id])
            //          .then((row)=> {
            //            if (row)
            //              return when.reject(new HttpError('That facebook id is already attached to a user.', 400))
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
            //          })
        });
    };

    Lawn.request = function (options, data, secure) {
        if (typeof data === "undefined") { data = null; }
        if (typeof secure === "undefined") { secure = false; }
        var def = when.defer();
        var http = require(secure ? 'https' : 'http');

        //    if (secure)
        //      options.secureProtocol = 'SSLv3_method'
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
            console.error('error', error.message, error.stack);

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
            user = socket.user;
            if (user)
                delete _this.instance_user_sockets[user.id][socket.id];

            delete _this.instance_sockets[socket.id];
            if (user && !_this.user_is_online(user.id)) {
                data = user;
                if (_this.ground.db['active'])
                    return _this.ground.db.query('UPDATE users SET online = 0 WHERE id = ' + user.id);
                //        data.online = false;
                //        return Server.notify.send_online_changed(user, false);
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
            if (status == 500)
                console.error('public http error:', status, error.message, error.stack || '');
            else
                console.error('public http error:', status, error.message, error.stack || '');
            res.status(status).json({ message: message });
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
        var _this = this;
        if (typeof method === "undefined") { method = 'post'; }
        this.app[method](path, function (req, res) {
            //        console.log('server recieved query request.')
            _this.process_user_http(req, res, action);
        });
    };

    Lawn.prototype.start_sockets = function (port) {
        var _this = this;
        if (typeof port === "undefined") { port = null; }
        var socket_io = require('socket.io');
        port = port || this.config.ports.websocket;
        console.log('Starting Socket.IO on port ' + port);

        var io = this.io = socket_io.listen(port);
        io.set('log level', process.argv.indexOf('--monitor-sockets') > -1 ? 3 : 1);
        io.server.on('error', function (e) {
            if (e.code == 'EADDRINUSE') {
                console.log('Port in use: ' + port + '.');
                _this.io = null;
            }
        });

        // Authorization
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

    Lawn.prototype.start_http = function (port) {
        var _this = this;
        if (!port)
            return;

        if (typeof this.config.max_connections == 'number') {
            var http = require('http');
            http.globalAgent.maxSockets = this.config.max_connections;
        }

        var express = require('express');
        var app = this.app = express();

        var parser = require('body-parser');
        app.use(parser.json());
        app.use(require('cookie-parser')());

        var session = require('express-session');
        if (!this.config.cookie_secret)
            throw new Error('lawn.cookie_secret must be set!');

        app.use(session({
            secret: this.config.cookie_secret, resave: true,
            saveUninitialized: true,
            store: new mysql_session(this.ground.db)
        }));

        app.use(function (req, res, next) {
            req.session.ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;
            next();
        });

        if (this.config.allow_cors === true) {
            app.use(require('cors')({
                origin: function (origin, callback) {
                    console.log('cors', origin);
                    callback(null, true);
                },
                credentials: true
            }));
            console.log('Using CORS');
        }

        // Log request info to a file
        if (typeof this.config.log_file === 'string') {
            var fs = require('fs');
            var log_file = fs.createWriteStream(this.config.log_file, { flags: 'a' });
            app.use(express.logger({ stream: log_file }));
        }

        // Hook login and logout for both GET and POST
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

        if (this.config.allow_register)
            this.listen_public_http('/vineyard/register', function (req, res) {
                return _this.register(req, res);
            });

        for (var i in this.services) {
            var service = this.services[i];
            if (service.http_path)
                this.create_service(service);
        }

        this.listen_public_http('/vineyard/password-reset', function (req, res) {
            return _this.password_reset_request(req, res, req.body);
        });

        // Deprecated in favor of a query using the new user parameter.
        this.listen_user_http('/vineyard/current-user', function (req, res, user) {
            res.send({
                status: 200,
                user: Lawn.format_public_user(user)
            });
            return when.resolve();
        }, 'get');

        //    this.listen_public_http('/vineyard/register', (req, res)=> this.register(req, res))
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
                    //              return when.reject({ status: 300, message: 'That Facebook user id is not yet connected to an account.  Redirect to registration.' })
                    //              var options = {
                    //                host: 'graph.facebook.com',
                    //                path: '/' + facebook_id + '?fields=name,username,gender,picture'
                    //                  + '&access_token=' + body.facebook_token,
                    //                method: 'GET'
                    //              }
                    //              return Lawn.request(options, null, true)
                    //                .then((response) => {
                    //                  console.log('fb-user', response.content)
                    //                  return this.create_user(facebook_id, response.content)
                    //                })
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

    var Mail = (function () {
        function Mail(config) {
            this.config = config;
            var nodemailer = require('nodemailer');
            var ses_transport = require('nodemailer-ses-transport');
            this.transporter = nodemailer.createTransport(ses_transport(config));
        }
        Mail.prototype.send = function (to, subject, text) {
            //    console.log('Sending email to ', to)
            var def = when.defer();
            console.log(this.config.address);
            this.transporter.sendMail({
                from: this.config.address,
                to: to,
                subject: subject,
                html: text
            }, function (error, info) {
                if (error) {
                    console.error('error', error);
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

    Lawn.HttpError;
    Lawn.Irrigation;
})(Lawn || (Lawn = {}));
Lawn.HttpError = HttpError;
Lawn.Irrigation = Irrigation;
/**
* User: Chris Johnson
* Date: 11/9/2014
*/
/// <reference path="../../vineyard/vineyard.d.ts"/>
///<reference path="../defs/socket.io.extension.d.ts"/>
///<reference path="../defs/express.d.ts"/>
/// <reference path="common.ts"/>
/// <reference path="gardener.ts"/>
/// <reference path="irrigation.ts"/>
/// <reference path="lawn.ts"/>
/**
* User: Chris Johnson
* Date: 11/9/2014
*/
/// <reference path="references.ts"/>
module.exports = Lawn
function typescript_bulb_export_hack() {
}
