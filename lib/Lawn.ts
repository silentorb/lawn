///<reference path="../defs/socket.io.extension.d.ts"/>
///<reference path="../defs/express.d.ts"/>
/// <reference path="references.ts"/>

declare var Irrigation

module Lawn {

  export interface Config {
    ports
    log_updates?:boolean
    use_redis?:boolean
    cookie_secret?:string
    log_file?:string
  }
}

class Lawn extends Vineyard.Bulb {
  io // Socket IO
  instance_sockets = {}
  instance_user_sockets = {}
  app
  fs
  config:Lawn.Config
  redis_client
  http
  debug_mode:boolean = false

  grow() {
    var ground = this.ground

    if (this.config.log_updates) {
      this.listen(ground, '*.update', (seed, update:Ground.Update):Promise => {
        // Don't want an infinite loop
        if (update.trellis.name == 'update_log')
          return when.resolve()

        return this.ground.insert_object('update_log', {
          user: update.user,
          data: JSON.stringify(seed),
          trellis: update.trellis.name
        })
      })
    }

    this.listen(ground, 'user.queried', (user, query:Ground.Query_Builder)=> this.query_user(user, query))
  }

  static
    authorization(handshakeData, callback) {
    return callback(null, true);
  }

  debug(...
          args:any[]) {
    var time = Math.round(new Date().getTime() / 10);
    var text = args.join(', ');
    console.log(text)
//      return this.ground.db.query("INSERT INTO debug (source, message, time) VALUES ('server', '" + text + "', " + time + ")");
  }

  get_user_socket(id:number):Socket {
    return this.instance_user_sockets[id]
  }

  initialize_session(socket, user) {
    this.instance_sockets[socket.id] = socket
    this.instance_user_sockets[user.id] = socket
    socket.join(user.id)

    socket.on('query', (request, callback)=> {
      Irrigation.process('query', request, user, this.vineyard, socket, callback)
//      Irrigation.query(request, user, this.ground, this.vineyard)
//        .done((objects)=> {
//          if (callback)
//            callback({ code: 200, 'message': 'Success', objects: objects })
//          else
//            socket.emit('error', {
//              'code': 400,
//              'message': 'Request must ask for an acknowledgement',
//              request: request
//            })
//        },
//        (error)=> {
//          callback({ code: 403, 'message': 'You are not authorized to perform this query.', objects: [] })
//          socket.emit('error', {
//            'code': 403,
//            'message': 'Unauthorized',
//            request: request
//          })
//        })
    })

    socket.on('update', (request, callback)=> {
      Irrigation.process('update', request, user, this.vineyard, socket, callback)
//      Irrigation.update(request, user, this.ground, this.vineyard)
//        .then((objects)=> {
//          if (callback)
//            callback({ code: 200, 'message': 'Success', objects: objects })
//          else
//            socket.emit('error', {
//              'code': 400,
//              'message': 'Request must ask for an acknowledgement',
//              request: request
//            })
//        },
//        (error)=> {
////          if (callback)
////            callback({ code: 403, 'message': 'You are not authorized to perform this update.', objects: [],
////              unauthorized_object: error.resource})
////          else
//          socket.emit('error', {
//            'code': 403,
//            'message': 'Unauthorized',
//            request: request,
//            unauthorized_object: error.resource
//          })
//        }
//      )
    })

    this.invoke('socket.add', socket, user)

    user.online = true
    socket.broadcast.emit('user.changed', { user: user })

    socket.on('disconnect', ()=> {
      console.log('emitting disconnect for socket', socket.id)
      user.online = false
      socket.broadcast.emit('user.changed', { user: user })
    })

    console.log(process.pid, 'Logged in: ' + user.id)
  }

  // Attach user online status to any queried users
  query_user(user, query:Ground.Query_Builder) {
    if (!this.io)
      return

    var clients = this.io.sockets.clients(user.id)
    user.online = clients.length > 0
  }

  start() {
    this.start_http(this.config.ports.http);
    this.start_sockets(this.config.ports.websocket);
  }

  get_user_from_session(token:string):Promise {
    var query = this.ground.create_query('session')
    query.add_key_filter(token)
    return query.run_single()
//      .then(()=> { throw new Error('Debug error') })
      .then((session) => {
        console.log('session', session)
        if (!session)
          return when.reject({status: 401, message: 'Session not found2.' })

        if (session.token === 0)
          return when.reject({status: 401, message: 'Invalid session.' })

        if (typeof session.user !== 'object')
          return when.reject({status: 401, message: 'User not found.' })

        return {
          id: session.user.id,
          name: session.user.name
        }
      })
  }

  http_login(req, res, body) {
    console.log('login', body)
    var mysql = require('mysql')
    this.ground.db.query("SELECT id, name FROM users WHERE name = ? AND password = ?", [body.name, body.pass])
//    this.ground.db.query("SELECT id, name FROM users WHERE name = '"+ body.name + "' AND password = '" + body.pass + "'")
      .then((rows)=> {
        if (rows.length == 0) {
          return res.status(401).send('Invalid login info.')
        }

        var user = rows[0];

        var session = [
          user.id,
          req.sessionID,
          req.host,
          Math.round(new Date().getTime() / 1000)
        ]
        console.log('insert-login', body)
        this.ground.db.query("REPLACE INTO sessions (user, token, hostname, timestamp) VALUES (?, ?, ?, ?)", session)
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
  }

  login(data, socket:ISocket, callback) {
    console.log('message2', data);
    if (!data.token)
      return socket.emit('error', { message: 'Missing token.' })

    var query = this.ground.create_query('session')
    query.add_key_filter(data.token)

    return this.get_user_from_session(data.token)
      .then((user)=> {
        this.initialize_session(socket, user);
        console.log('user', user)
        if (callback) {
          console.log('login callback called')
          callback(user)
        }
      },
      (error)=> {
        if (this.debug_mode) {
          console.log('error', error.message)
          console.log('stack', error.stack)
        }

        socket.emit('error', {
          'message': error.status == 500 || !error.message ? 'Error getting session.' : error.message
        })
      }
    )
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
        this.debug(user.id);
        data = user
        data.online = false;
//        return Server.notify.send_online_changed(user, false);
      }
    });
  }

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

  process_public_http_request(req, res, action) {

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

    app.use(express.session({secret: this.config.cookie_secret}))

    // Log request info to a file
    if (typeof this.config.log_file === 'string') {
      var fs = require('fs')
      var log_file = fs.createWriteStream(this.config.log_file, {flags: 'a'})
      app.use(express.logger({stream: log_file}))
    }

    app.post('/vineyard/login', (req, res)=> this.http_login(req, res, req.body))
    app.get('/vineyard/login', (req, res)=> this.http_login(req, res, req.query))

    app.post('/vineyard/query', (req, res):any => {
      this.get_user_from_session(req.sessionID)
        .then((user) => {

          console.log('files', req.files)
          console.log('req.body', req.body)
          var request = req.body

          return Irrigation.query(request, user, this.ground, this.vineyard)
            .then((objects)=> res.send({ message: 'Success', objects: objects })
          )
        })
        .otherwise((error)=> {
          res.json(error.status || 500, { message: error.message })
        })
    })

//    app.post('/vineyard/update', (req, res):any => {
//      this.get_user_from_session(req.sessionID)
//        .then((user) => {
//
//          console.log('files', req.files)
//          console.log('req.body', req.body)
//          var request = JSON.parse(req.body)
//
//          Irrigation.update(request, user, this.ground, this.vineyard)
//            .then((objects)=> callback({ code: 200, 'message': 'Success', objects: objects}),
//            (error)=> {
//              callback({ code: 403, 'message': 'You are not authorized to perform this update.', objects: [] })
//              socket.emit('error', {
//                'code': 401,
//                'message': 'Unauthorized',
//                request: request
//              })
//            })
//        },
//        (error)=> res.status(error.status).send(error.message)
//      )
//    })

    app.post('/vineyard/upload', (req, res):any => {
      this.get_user_from_session(req.sessionID)
        .then((user) => {

          console.log('files', req.files)
          console.log('req.body', req.body)
          var info = JSON.parse(req.body.info)
          var file = req.files.file;
          var guid = info.guid;
          if (!guid)
            return res.status(401).send('guid is empty.')

          if (!guid.match(/[\w\-]+/))
            return res.status(401).send('Invalid guid.')

          var path = require('path')
          var ext = path.extname(file.originalFilename) || ''
          var filename = guid + ext
          var filepath = 'files/' + filename
          var fs = require('fs')
          fs.rename(file.path, filepath);

          // !!! Add check if file already exists
          this.ground.update_object('file', {
            guid: guid,
            name: filename,
            path: file.path,
            size: file.size,
            extension: ext.substring(1),
            status: 1
          }, user)
            .then((object)=> res.send({file: object}))
        },
        (error)=> res.status(error.status).send(error.message)
      )
    })

    app.get('/file/:guid.:ext', (req, res)=> {
      var guid = req.params.guid;
      var ext = req.params.ext;
      if (!guid.match(/[\w\-]+/) || !ext.match(/\w+/)) {
        return res.status(401).send('Invalid File Name')
      }
      var fs = require('fs')
      var path = require('path')
      var filepath = path.join(this.vineyard.root_path, 'files', guid + '.' + ext)
      console.log(filepath)
      fs.exists(filepath, (exists)=> {
        if (!exists)
          return res.status(404).send('File Not Found')

        var query = this.ground.create_query('file')
        query.add_key_filter(req.params.guid)
        var fortress = this.vineyard.bulbs.fortress

        this.get_user_from_session(req.sessionID)
          .then((user)=> fortress.query_access(user, query))
          .then((result)=> {
            if (result.access)
              res.sendfile(filepath)
            else
              res.status(403).send('Access Denied')
          },
          ()=> res.status(500).send('Internal Server Error')
        )
//          res.end()
      })
    })
    port = port || this.config.ports.http
    console.log('HTTP listening on port ' + port + '.')

    this.http = app.listen(port)
  }

  stop() {
    // Socket IO's documentation is a joke.  I had to look on stack overflow for how to close a socket server.
    if (this.io && this.io.server) {
      this.io.server.close()
      this.io = null
    }

    if (this.redis_client) {
      this.redis_client.quit()
      this.redis_client = null
    }

    if (this.http) {
      console.log('Closing HTTP connection.')
      this.http.close()
      this.http = null
      this.app = null
    }
  }

}

module
Lawn {

  export
  interface
  Update_Request {
    objects:any[];
  }

  class HttpError {
    name = "HttpError"
    message
    stack
    status
    details

    constructor(message:string, status = 500) {
      this.message = message
      this.status = status
    }
  }

  class Authorization_Error extends HttpError {
    details

    constructor(message:string, details) {
      super(message, 403)
      this.details = details
    }
  }

  export class Irrigation {
    static process(method:string, request:Ground.External_Query_Source, user:Vineyard.IUser, vineyard:Vineyard, socket, callback):Promise {
      var fortress = vineyard.bulbs.fortress
      var action = Irrigation[method]
      return fortress.get_roles(user)
        .then(()=> action(request, user, vineyard.ground, vineyard))
        .then((objects)=> {
          if (callback)
            callback({ code: 200, 'message': 'Success', objects: objects })
          else
            socket.emit('error', {
              status: 400,
              message: 'Requests need to ask for an acknowledgement',
              request: request
            })
        },
        (error)=> {
//          if (callback)
//            callback({ code: 403, 'message': 'You are not authorized to perform this update.', objects: [],
//              unauthorized_object: error.resource})
//          else
          error = error || {}
          console.log('service error:', error.message, error.status, error.stack)
          var status = error.status || 500

          var response = {
            code: status,
            status: status,
            request: request,
            details: error.details,
            message: error.message || "Server Error"
          }

          if (fortress.user_has_role(user, 'admin')) {
            response.message = status == 500 ? 'Server Error' : error.message || "Server Error"
            response['stack'] = error.stack
          }

          if (vineyard.bulbs.lawn.debug_mode)
            console.log('error', error.stack)

          socket.emit('error', response)
        })
    }

    static query(request:Ground.External_Query_Source, user:Vineyard.IUser, ground:Ground.Core, vineyard:Vineyard):Promise {
      if (!request)
        throw new HttpError('Empty request', 400)

      var trellis = ground.sanitize_trellis_argument(request.trellis);
      var query = new Ground.Query_Builder(trellis);

      query.extend(request)

      var fortress = vineyard.bulbs.fortress
      return fortress.query_access(user, query)
        .then((result)=> {
          if (result.access)
            return query.run();
          else
            throw new Authorization_Error('You are not authorized to perform this query', result)
        })
    }

    static update(request:Update_Request, user:Vineyard.IUser, ground:Ground.Core, vineyard:Vineyard):Promise {
      var updates = request.objects.map((object)=>
          ground.create_update(object.trellis, object, user)
      )

      if (!request.objects)
        throw new HttpError('Request requires an objects array', 400);

      var fortress = vineyard.bulbs.fortress
      return fortress.update_access(user, updates)
        .then((result)=> {
          if (result.access) {
            var update_promises = updates.map((update) => update.run())
            return when.all(update_promises)
          }
          else
            throw new Authorization_Error('You are not authorized to perform this update', result)
        })


    }
  }
}