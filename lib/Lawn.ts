/**
 * User: Chris Johnson
 * Date: 10/2/13
 */
///<reference path="../defs/socket.io.extension.d.ts"/>
///<reference path="../defs/express.d.ts"/>
/// <reference path="references.ts"/>
declare var Irrigation

export class Lawn extends Vineyard.Bulb {
  io // Socket IO
  instance_sockets = {}
  instance_user_sockets = {}
  private app:ExpressApplication
  fs
  config
  redis_client

  static authorization(handshakeData, callback) {
//      console.log('authorizing', handshakeData);
    return callback(null, true);
  }

  debug(...args:any[]) {
    var time = Math.round(new Date().getTime() / 10);
    var text = args.join(', ');
    console.log(text)
//      return this.ground.db.query("INSERT INTO debug (source, message, time) VALUES ('server', '" + text + "', " + time + ")");
  }

  get_user_socket(id:number):Socket {
    return this.instance_user_sockets[id]
  }

  initialize_session(socket, user) {
    var _this = this;
    this.instance_sockets[socket.id] = socket
    this.instance_user_sockets[user.id] = socket
//      socket.emit('login-success', {
//        user: user.simple()
//      });
    socket.join('test room')

    socket.on('query', (request, callback)=> {
      Irrigation.query(request, this.ground, this.vineyard)
        .then((response)=> callback(response))
    })

    socket.on('update', (request, callback)=> {
      console.log('vineyard update:', request)
      Irrigation.update(request, user.guid, this.ground, this.vineyard)
        .then((response)=> callback(response))
    })

    console.log(process.pid, 'Logged in: ' + user.id)
  }

  start() {
    this.start_http(this.config.ports.http);
    this.start_sockets(this.config.ports.websocket);
  }

  login(data, socket:ISocket, callback) {
    console.log('message2', data);
    if (!data.token)
      return socket.emit('error', {
        'message': 'Missing token.'
      });
    var query = this.ground.create_query('session')
    query.add_key_filter(data.token)
    query.add_property_filter('user', data.user)
    return query.run_single()
      .then((session) => {
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
        var query = this.ground.create_query('user')
        query.add_key_filter(data.user)
        return query.run_single()
          .then((user_record) => {
            if (!user_record) {
              socket.emit('error', {
                'message': 'User not found.'
              });
              return;
            }
            var user = socket.user = user_record;
//            user.session = session;
            this.initialize_session(socket, user);
            console.log('user', user_record)
            callback(user_record)
          });
      },
      (error) => {
        return socket.emit('error', {
          'message': error
        });
      });
  }

  on_connection(socket:ISocket) {
    console.log('connection attempted')
    socket.on('login', (data, callback)=> this.login(data, socket, callback));

    socket.emit('connection');
    return socket.on('disconnect', () => {
      var data, user;
      this.debug('***detected disconnect');
      user = socket.user;
      delete this.instance_sockets[socket.id];
      if (user && !this.get_user_socket(user.id)) {
        console.log('good', user.simple());
        this.debug(user.id);
        data = user.simple();
        data.online = false;
//        return Server.notify.send_online_changed(user, false);
      }
    });
  }

//    start(http_port = null, socket_port = null) {
//      this.start_http(http_port || this.config.ports.http);
//      this.start_sockets(socket_port || this.config.ports.websocket);
//    }

  start_sockets(port = null) {
    var socket_io = require('socket.io')
    port = port || this.config.ports.websocket
    console.log('Starting Socket.IO on port ' + port)

    var io = this.io = socket_io.listen(port)
    io.server.on('error', (e)=> {
      if (e.code == 'EADDRINUSE') {
        console.log('Port in use: ' + port + '.')
        this.io = null
      }
    })
    // Authorization
    io.configure(()=>
      io.set('authorization', Lawn.authorization))

    io.sockets.on('connection', (socket)=>this.on_connection(socket))

    if (this.config.use_redis) {
      console.log('using redis')
      var RedisStore = require('socket.io/lib/stores/redis')
        , redis = require("socket.io/node_modules/redis")
        , pub = redis.createClient()
        , sub = redis.createClient()
        , client = redis.createClient()

      io.set('store', new RedisStore({
        redisPub: pub, redisSub: sub, redisClient: client
      }))
    }
  }

  start_http(port) {
    if (!port)
      return

    var express = require('express');
    var app = this.app = express();

    app.use(express.bodyParser({ keepExtensions: true, uploadDir: "tmp"}));
    app.use(express.cookieParser());
    if (!this.config.cookie_secret)
      throw new Error('lawn.cookie_secret must be set!')

    app.use(express.session({secret: this.config.cookie_secret}));

    var user;
    app.post('/vineyard/login', (req, res)=> {
      this.ground.db.query("SELECT id, name FROM users WHERE name = ? AND pass = ?", [req.body.name, req.body.pass])
        .then((rows)=> {
          if (rows.length == 0) {
            return res.status(401).send('Invalid login info.')
          }

          user = rows[0];

          var session = [
            user.id,
            req.sessionID,
            req.host,
            Math.round(new Date().getTime() / 1000)
          ]
          this.ground.db.query("REPLACE INTO sessions (id, token, hostname, timestamp) VALUES (?, ?, ?, ?)", session)
            .then(()=> {
              res.send({
                token: req.sessionID,
                message: 'Login successful',
                user: {
                  id: user.id,
                  name: user.name
                }
              });
            })
        })
    });

    app.post('/vineyard/upload', (req, res):any => {
        console.log('files', req.files)
        console.log('req.body', req.body)
        var info = JSON.parse(req.body.info)
        var file = req.files.file;
        var id = info.id;
        if (!id.match(/[\w\-]+/)) {
          return res.status(401).send('Invalid id')
        }
        var path = require('path')
        var ext = path.extname(file.originalFilename)
        var filename = id + ext
        var filepath = 'files/' + filename
        this.fs.rename(file.path, filepath);

        // !!! Add check if file already exists
        this.ground.update_object('file', {
          gid: info.id,
          name: filename,
          path: path,
          size: file.size
        }, user.id)
          .then((object)=> res.send({file: object}))
      }
    )

    app.get('/file/:id.:ext', function (req, res):any {
      var id = req.params.id;
      var ext = req.params.ext;
      if (!id.match(/[\w\-]+/) || !ext.match(/\w+/)) {
        return res.status(401).send('Invalid file name')
      }
      var fs = require('fs')
      var path = require('path')
      var filepath = path.join(__dirname, '../files', id + '.' + ext)
      console.log(filepath)
      fs.exists(filepath, function (exists):any {
        if (!exists)
          return res.status(404).send('Not found')

        res.sendfile(filepath)
//          res.end()
      })
    })
    port = port || this.config.ports.http
    console.log('HTTP listening on port ' + port + '.')

    app.listen(port)
  }

  stop() {
    // Socket IO's documentation is a joke.  I had to look on stack overflow for how to close a socket server.
    if (this.io && this.io.server)
      this.io.server.close();

    if (this.redis_client)
      this.redis_client.quit()
  }

}
