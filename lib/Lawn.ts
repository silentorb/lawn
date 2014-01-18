///<reference path="../defs/socket.io.extension.d.ts"/>
///<reference path="../defs/express.d.ts"/>
/// <reference path="references.ts"/>

declare var Irrigation

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

    socket.on('query', (request, callback)=>
        Irrigation.process('query', request, user, this.vineyard, socket, callback)
    )

    socket.on('update', (request, callback)=>
        Irrigation.process('update', request, user, this.vineyard, socket, callback)
    )

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
    query.add_subquery('user').add_subquery('roles')

    return query.run_single()
//      .then(()=> { throw new Error('Debug error') })
      .then((session) => {
        console.log('session', session)
        if (!session)
          throw new Lawn.HttpError('Session not found.', 400)

        if (session.token === 0)
          throw new Lawn.HttpError('Invalid session.', 400)

        if (typeof session.user !== 'object')
          throw new Lawn.HttpError('User not found.', 400)

        var user = session.user
        return {
          id: user.id,
          name: user.name,
          roles: user.roles
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

  static process_public_http(req, res, action) {
    try {
      action(req, res)
    }
    catch (error) {
      var status = error.status || 500
      var message = status == 500 ? 'Server Error' : error.message
      res.json(status || 500, { message: message })
    }
  }

  static listen_public_http(app, path, action, method = 'post') {
    app[method](path, (req, res)=>
        Lawn.process_public_http(req, res, action)
    )
  }

  process_error(error, user) {
    var status = error.status || 500
    var message = status == 500 ? 'Server Error' : error.message

    var response = {
      status: status,
      message: message
    }

    var fortress = this.vineyard.bulbs.fortress
    if (user && fortress && fortress.user_has_role(user, 'admin')) {
      response.message = error.message || "Server Error"
      response['stack'] = error.stack
      response['details'] = error.details
    }

    console.log('service error:', status, error.message, error.stack)

    return response
  }

  process_user_http(req, res, action) {
    var user = null, send_error = (error)=> {
      console.log('yeah')
      var response = this.process_error(error, user)
      var status = response.status
      delete response.status
      res.json(status, response)
    }
    try {
      this.get_user_from_session(req.sessionID)
        .then((u)=> {
          user = u
          return action(req, res, user)
        })
        .done(()=> {
        }, send_error)
    }
    catch (error) {
      send_error(error)
    }
  }

  listen_user_http(path, action, method = 'post') {
    this.app[method](path, (req, res)=> {
        console.log('server recieved query request.')
        this.process_user_http(req, res, action)
      }
    )
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

  private static file_exists(filepath:string):Promise {
    var fs = require('fs'), def = when.defer()
    fs.exists(filepath, (exists)=> {
      def.resolve(exists)
    })
    return def.promise
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
    this.listen_user_http('/vineyard/query', (req, res, user)=> {
      console.log('server recieved query request.')
      return Irrigation.query(req.body, user, this.ground, this.vineyard)
        .then((objects)=> res.send({ message: 'Success', objects: objects })
      )
    })

    this.listen_user_http('/vineyard/upload', (req, res, user)=> {
      console.log('files', req.files)
      console.log('req.body', req.body)
      var info = JSON.parse(req.body.info)
      var file = req.files.file;
      var guid = info.guid;
      if (!guid)
        throw new Lawn.HttpError('guid is empty.', 400)

      if (!guid.match(/[\w\-]+/))
        throw new Lawn.HttpError('Invalid guid.', 400)

      var path = require('path')
      var ext = path.extname(file.originalFilename) || ''
      var filename = guid + ext
      var filepath = 'files/' + filename
      var fs = require('fs')
      fs.rename(file.path, filepath);

      // !!! Add check if file already exists
      return this.ground.update_object('file', {
        guid: guid,
        name: filename,
        path: file.path,
        size: file.size,
        extension: ext.substring(1),
        status: 1
      }, user)
        .then((object)=> {
          res.send({file: object})
          this.invoke('file.uploaded', object)
        })
    })

    this.listen_user_http('/file/:guid.:ext', (req, res, user)=> {
      var guid = req.params.guid;
      var ext = req.params.ext;
      if (!guid.match(/[\w\-]+/) || !ext.match(/\w+/))
        throw new Lawn.HttpError('Invalid File Name', 400)

      var path = require('path')
      var filepath = path.join(this.vineyard.root_path, 'files', guid + '.' + ext)
      console.log(filepath)
      return Lawn.file_exists(filepath)
        .then((exists)=> {
          if (!exists)
//          throw new Lawn.HttpError('File Not Found', 404)
            throw new Error('File Not Found2')

          var query = this.ground.create_query('file')
          query.add_key_filter(req.params.guid)
          var fortress = this.vineyard.bulbs.fortress

          fortress.query_access(user, query)
            .then((result)=> {
              if (result.access)
                res.sendfile(filepath)
              else
                throw new Lawn.HttpError('Access Denied', 403)
            })
        })
    }, 'get')

    port = port || this.config.ports.http
    console.log('HTTP listening on port ' + port + '.')

    this.invoke('http.start', app, this)
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

module Lawn {

  export interface Config {
    ports
    log_updates?:boolean
    use_redis?:boolean
    cookie_secret?:string
    log_file?:string
  }

  export interface Update_Request {
    objects:any[];
  }

  export class HttpError {
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

  export class Authorization_Error extends HttpError {
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
          else if (method != 'update')
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
            message: status == 500 ? "Server Error" : error.message
          }

          if (fortress.user_has_role(user, 'admin')) {
            response.message = error.message || "Server Error"
            response['stack'] = error.stack
            details: error.details
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
      if (!MetaHub.is_array(request.objects))
        throw new HttpError('Update is missing objects list.', 400)

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