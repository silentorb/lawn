var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
var Lawn = (function (_super) {
    __extends(Lawn, _super);
    function Lawn() {
        _super.apply(this, arguments);
        this.instance_sockets = {};
        this.instance_user_sockets = {};
    }
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

    Lawn.prototype.get_user_socket = function (id) {
        return this.instance_user_sockets[id];
    };

    Lawn.prototype.initialize_session = function (socket, user) {
        var _this = this;
        var _this = this;
        this.instance_sockets[socket.id] = socket;
        this.instance_user_sockets[user.id] = socket;

        socket.join('test room');

        socket.on('query', function (request, callback) {
            Irrigation.query(request, _this.ground, _this.vineyard).then(function (response) {
                return callback(response);
            });
        });

        socket.on('update', function (request, callback) {
            console.log('vineyard update:', request);
            Irrigation.update(request, user.guid, _this.ground, _this.vineyard).then(function (response) {
                return callback(response);
            });
        });

        console.log(process.pid, 'Logged in: ' + user.id);
    };

    Lawn.prototype.start = function () {
        this.start_http(this.config.ports.http);
        this.start_sockets(this.config.ports.websocket);
    };

    Lawn.prototype.login = function (data, socket, callback) {
        var _this = this;
        console.log('message2', data);
        if (!data.token)
            return socket.emit('error', {
                'message': 'Missing token.'
            });
        var query = this.ground.create_query('session');
        query.add_key_filter(data.token);
        query.add_property_filter('user', data.user);
        return query.run_single().then(function (session) {
            if (!session) {
                return socket.emit('error', {
                    'message': 'Session not found.'
                });
            }
            if (session.id === 0) {
                return socket.emit('error', {
                    'message': 'Invalid session.'
                });
            }
            var query = _this.ground.create_query('user');
            query.add_key_filter(data.user);
            return query.run_single().then(function (user_record) {
                if (!user_record) {
                    socket.emit('error', {
                        'message': 'User not found.'
                    });
                    return;
                }
                var user = socket.user = user_record;

                _this.initialize_session(socket, user);
                console.log('user', user_record);
                callback(user_record);
            });
        }, function (error) {
            return socket.emit('error', {
                'message': error
            });
        });
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
            delete _this.instance_sockets[socket.id];
            if (user && !_this.get_user_socket(user.id)) {
                console.log('good', user.simple());
                _this.debug(user.id);
                data = user.simple();
                data.online = false;
            }
        });
    };

    Lawn.prototype.start_sockets = function (port) {
        if (typeof port === "undefined") { port = null; }
        var _this = this;
        var socket_io = require('socket.io');
        port = port || this.config.ports.websocket;
        console.log('Starting Socket.IO on port ' + port);

        var io = this.io = socket_io.listen(port);
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
                redisPub: pub,
                redisSub: sub,
                redisClient: client
            }));
        }
    };

    Lawn.prototype.start_http = function (port) {
        var _this = this;
        if (!port)
            return;

        var express = require('express');
        var app = this.app = express();

        app.use(express.bodyParser({ keepExtensions: true, uploadDir: "tmp" }));
        app.use(express.cookieParser());
        if (!this.config.cookie_secret)
            throw new Error('lawn.cookie_secret must be set!');

        app.use(express.session({ secret: this.config.cookie_secret }));

        var user;
        app.post('/vineyard/login', function (req, res) {
            _this.ground.db.query("SELECT id, name FROM users WHERE name = ? AND pass = ?", [req.body.name, req.body.pass]).then(function (rows) {
                if (rows.length == 0) {
                    return res.status(401).send('Invalid login info.');
                }

                user = rows[0];

                var session = [
                    user.id,
                    req.sessionID,
                    req.host,
                    Math.round(new Date().getTime() / 1000)
                ];
                _this.ground.db.query("REPLACE INTO sessions (id, token, hostname, timestamp) VALUES (?, ?, ?, ?)", session).then(function () {
                    res.send({
                        token: req.sessionID,
                        message: 'Login successful',
                        user: {
                            id: user.id,
                            name: user.name
                        }
                    });
                });
            });
        });

        app.post('/vineyard/upload', function (req, res) {
            console.log('files', req.files);
            console.log('req.body', req.body);
            var info = JSON.parse(req.body.info);
            var file = req.files.file;
            var id = info.id;
            if (!id.match(/[\w\-]+/)) {
                return res.status(401).send('Invalid id');
            }
            var path = require('path');
            var ext = path.extname(file.originalFilename);
            var filename = id + ext;
            var filepath = 'files/' + filename;
            _this.fs.rename(file.path, filepath);

            _this.ground.update_object('file', {
                gid: info.id,
                name: filename,
                path: path,
                size: file.size
            }, user.id).then(function (object) {
                return res.send({ file: object });
            });
        });

        app.get('/file/:id.:ext', function (req, res) {
            var id = req.params.id;
            var ext = req.params.ext;
            if (!id.match(/[\w\-]+/) || !ext.match(/\w+/)) {
                return res.status(401).send('Invalid file name');
            }
            var fs = require('fs');
            var path = require('path');
            var filepath = path.join(__dirname, '../files', id + '.' + ext);
            console.log(filepath);
            fs.exists(filepath, function (exists) {
                if (!exists)
                    return res.status(404).send('Not found');

                res.sendfile(filepath);
            });
        });
        port = port || this.config.ports.http;
        console.log('HTTP listening on port ' + port + '.');

        app.listen(port);
    };

    Lawn.prototype.stop = function () {
        if (this.io && this.io.server)
            this.io.server.close();

        if (this.redis_client)
            this.redis_client.quit();
    };
    return Lawn;
})(Vineyard.Bulb);
exports.Lawn = Lawn;

//# sourceMappingURL=Lawn.js.map
