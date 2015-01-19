/// <reference path="references.ts"/>


interface User_Source {
	name?:string
	display_name?:string
	username:string
	password:string
	email?:string
	phone?:string
	gender?:string
	facebook_token?:string
	image?:string
	address?
}

class Lawn extends Vineyard.Bulb {
	io // Socket IO
	instance_sockets = {}
	instance_user_sockets = {}
	app
	config:Lawn.Config
	redis_client
	http
	debug_mode:boolean = false
	mail:Lawn.Mail = null
	password_reset_template:string = null

	private services:Service_Definition[] = []

	grow() {
		var ground = this.ground

		// Lawn requires vineyard-user whether or not it was included in the site config files.
		var user_bulb = this.vineyard.bulbs['user']
		if (!user_bulb) {
			user_bulb = this.vineyard.load_bulb('user', {
				path: require('path').resolve(__dirname, 'node_modules/vineyard-user')
			})
		}

		this.config.display_name_key = this.config.display_name_key || 'display_name'

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

		if (this.config.mail)
			this.mail = new Lawn.Mail(this.config.mail)

		if (this.config.password_reset_template) {
			var fs = require('fs')
			this.password_reset_template = fs.readFileSync(this.config.password_reset_template, 'ascii')
		}

		this.config['valid_username'] = typeof this.config.valid_username == 'string'
			? new RegExp(this.config.valid_username)
			: /^[A-Za-z\-_0-9]+$/

		this.config['valid_password'] = typeof this.config.valid_password == 'string'
			? new RegExp(this.config.valid_password)
			: /^[A-Za-z\- _0-9!@#\$%\^&\*\(\)?]+$/

		this.config['valid_display_name'] = typeof this.config.valid_display_name == 'string'
			? new RegExp(this.config.valid_display_name)
			: /^[A-Za-z\-_0-9]+$/

		Irrigation.grow(this)

		Gardener.grow(this)
	}

	static authorization(handshakeData, callback) {
		return callback(null, true);
	}

	emit_to_users(users, name, data):Promise {
		throw new Error("Lawn.emit_to_users was removed.")
		//return this.vineyard.bulbs.songbird.notify(users, name, data)
	}

	notify(user, name, data, trellis_name:string):Promise {
		console.warn("Lawn.notify() is deprecated.  Use Songbird.notify() instead.")
		return this.vineyard.bulbs.songbird.notify(user, name, data, trellis_name)
	}

	get_user_sockets(id:number):Socket[] {
		return MetaHub.map_to_array(this.instance_user_sockets[id], (x)=> x)
			|| []
	}

	initialize_session(socket, user) {
		socket.user = user
		this.instance_sockets[socket.id] = socket
		this.instance_user_sockets[user.id] = this.instance_user_sockets[user.id] || []
		this.instance_user_sockets[user.id][socket.id] = socket
		this.ground.db.query('UPDATE users SET online = 1 WHERE id = ' + user.id)

		socket.join('user/' + user.id)

		//socket.on('query', (request, callback)=>
		//    Irrigation.process('query', request, user, this.vineyard, socket, callback)
		//)
		//
		//socket.on('update', (request, callback)=>
		//    Irrigation.process('update', request, user, this.vineyard, socket, callback)
		//)

		this.on_socket(socket, 'room/join', user, (request)=> {
				console.log('room/join', user.id, request)
				socket.join(request.room)
			}
		)

		this.on_socket(socket, 'room/leave', user, (request)=> {
				console.log('room/leave', user.id, request)
				socket.leave(request.room)
			}
		)

		this.on_socket(socket, 'room/emit', user, (request)=> {
				console.log('room/emit', user.id, request)
				socket.broadcast.to(request.room).emit(request.event_name, request.data) //emit to 'room' except this socket
			}
		)

		for (var i in this.services) {
			var service = this.services[i]
			if (service.socket_path)
				this.create_socket_service(socket, user, service)
		}

		user.online = true
		this.invoke('socket.add', socket, user)

		console.log(process.pid, 'Logged in: ' + user.id)
	}

	// Attach user online status to any queried users
	query_user(user, query:Ground.Query_Builder) {
		if (!this.io)
			return

		var clients = this.io.sockets.clients(user.id)
	}

	start() {
		if (!this.vineyard.bulbs.fortress)
			console.log("WARNING: Fortress is not loaded.  Server will be running with minimal security.")

		return this.ground.db.query("UPDATE users SET online = 0 WHERE online = 1")
			.then(()=> {
				this.start_http(this.config.ports.http);
				this.start_sockets(this.config.ports.websocket);
			})
	}

	static public_user_properties = ['id', 'name', 'username', 'email']
	static internal_user_properties = Lawn.public_user_properties.concat(['roles'])

	private static is_ready_user_object(user) {
		var properties = Lawn.public_user_properties
		for (var i = 0; i < properties.length; ++i) {
			if (user[properties[i]] === undefined)
				return false
		}

		return true
	}

	private static format_public_user(user) {
		return MetaHub.extend({}, user, Lawn.public_user_properties)
	}

	private static format_internal_user(user) {
		var result = MetaHub.extend({}, user)
		delete result.password
		return result
	}

	get_public_user(user):Promise {
		if (typeof user == 'object') {
			if (Lawn.is_ready_user_object(user)) {
				return when.resolve(Lawn.format_public_user(user))
			}
		}

		var id = typeof user == 'object' ? user.id : user
		var query = this.ground.create_query('user')
		query.add_key_filter(id)
		return query.run_single(null)
			.then((user)=> Lawn.format_public_user(user))
	}

	get_schema(req, res, user) {
		var fortress = this.vineyard.bulbs.fortress
		var response = !fortress || fortress.user_has_role(user, 'admin')
			? this.ground.export_schema()
			: {}

		res.send(response)
	}

	get_user_from_session(token:string):Promise {
		var query = this.ground.create_query('session')
		query.add_key_filter(token)
		query.add_subquery('user').add_subquery('roles')

		return query.run_single(null)
			.then((session) => {
				//console.log('session', session)
				var user = !session || session.token === 0 || typeof session.user !== 'object'
					? {id: 2, username: 'anonymous', roles: [{id: 3, name: 'anonymous'}]}
					: session.user

				return Lawn.format_internal_user(user)
			})
	}

	http_login(req, res, body):Promise {

		if (typeof body.facebook_token === 'string')
			return this.vineyard.bulbs.facebook.login(req, res, body)

		var user_bulb = this.vineyard.bulbs['user']

		var username = body.username || body.name
		var password = user_bulb.prepare_password(body.password || body.pass)

		var sql = "SELECT id, " + this.config.display_name_key
			+ ", status FROM users WHERE username = ? AND password = ?"

		console.log('login', body)
		return this.ground.db.query_single(sql, [username, password])
			.then((user)=> {
				if (user)
					return when.resolve(user)

				var sql = "SELECT users.id, users.username, users.status, requests.password as new_password FROM users "
					+ "\nJOIN password_reset_requests requests ON requests.user = users.id"
					+ "\nWHERE users.username = ? AND requests.password = ?"
					+ "\nAND requests.used = 0"
					+ "\nAND requests.created > UNIX_TIMESTAMP() - 12 * 60 * 60"
				console.log('sql', sql)
				return this.ground.db.query_single(sql, [username, password])
					.then((user)=> {
						console.log('hey', user, [username, password])
						if (!user)
							throw new HttpError('Invalid username or password.', 400)

						if (user.status === 0)
							throw new Authorization_Error('This account has been disabled.', user)

						password = user.new_password
						delete user.new_password
						return this.ground.db.query("UPDATE users SET password = ? WHERE id = ?", [password, user.id])
							.then(()=> this.ground.db.query(
								"UPDATE password_reset_requests SET used = 1, modified = UNIX_TIMESTAMP()"
								+ "\nWHERE password = ? AND user = ?", [password, user.id]))
							.then(()=> user)
					})
			})
			.then((user)=> {
				if (!user)
					throw new HttpError('Invalid login info.', 400)

				if (user.status === 0)
					throw new Authorization_Error('This account has been disabled.', user)

				if (user.status === 2)
					throw new Authorization_Error('This account is awaiting email verification.', user)

				var roles_sql = 'SELECT * FROM roles'
					+ '\nJOIN roles_users ON roles.id = roles_users.role'
					+ '\nWHERE user = ?'
				return this.ground.db.query(roles_sql, [user.id])
					.then((roles)=> {
						user.roles = roles
						return this.invoke('user.login', user, body)
					})
					.then(()=> {
						return Lawn.create_session(user, req, this.ground)
							.then(()=> this.send_http_login_success(req, res, user, body))
					})
			})
	}

	logout(req, res, user) {
		var sql = "DELETE FROM sessions WHERE user = ? AND token = ?"
		return this.ground.db.query(sql, [user.id, req.sessionID])
			.then(()=> res.json({key: 'logged-out'}))
	}

	is_configured_for_password_reset():boolean {
		return this.config.site
			&& this.config.site.name
			&& this.mail
			&& typeof this.password_reset_template == 'string'
	}

	check_password_reset_configuration(req, res, body):Promise {
		return this.is_configured_for_password_reset()
			? when.resolve()
			: when.reject({
			status: 400,
			message: "This site is not configured to support resetting passwords.",
			key: "vineyard-password-not-configured"
		})
	}

	password_reset_request(req, res, body):Promise {
		return this.check_password_reset_configuration(req, res, body)
			.then(() => this.ground.db.query_single("SELECT * FROM users WHERE username = ?", [body.username]))
			.then((user) => {
				if (!user) {
					return when.reject({
						status: 400,
						message: "There is no user with that username.",
						key: "vineyard-password-reset-user-not-found"
					})
				}
				if (!user.email) {
					return when.reject({
						status: 400,
						message: "An email address is required to reset your password, and your account does not have an email address.",
						key: "vineyard-password-reset-no-email-address"
					})
				}
				var sql = "SELECT * FROM password_reset_requests"
					+ "\nJOIN users ON users.id = password_reset_requests.id AND users.username = ?"
					+ "\nWHERE password_reset_requests.created > UNIX_TIMESTAMP() - 12 * 60 * 60"
					+ "\nORDER BY used DESC"
				return this.ground.db.query_single(sql, [body.username])
					.then((row)=> {
						if (row) {
							if (row.used) {
								res.send({
									message: "Your password was recently reset.  You must wait 12 hours before resetting it again.",
									key: "vineyard-password-reset-recently"
								})
							}
							else {
								res.send({
									message: "An email with a temporary password was recently sent to you.",
									key: "vineyard-password-reset-already-sent"
								})
							}
						}
						else {
							return this.create_password_reset_entry(user.id)
								.then((entry)=> {
									var email = {
										title: this.config.site.name + " Password Reset",
										content: this.password_reset_template
											.replace(/\{name}/g, user.username)
											.replace(/\{password}/g, entry.password)
									}
									return this.invoke('compose-password-reset-email', email)
										.then(()=> {
											return this.mail.send(user.email, email.title, email.content)
												.then(()=> {
													res.send({
														message: "A tempory password was sent to your email.",
														key: "vineyard-password-reset-sent"
													})
												})
										})
								})
						}
						return when.resolve()
					})
			})
	}

	create_password_reset_entry(user_id):Promise {
		function generate_password() {
			var range = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
			var result = ''
			for (var i = 0; i < 8; ++i) {
				result += range[Math.floor(Math.random() * range.length)]
			}

			return result
		}

		var password = generate_password()

		var sql = "INSERT INTO password_reset_requests (`user`, `password`, `created`, `modified`, `used`)"
			+ " VALUES (?, ?, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 0)"
		return this.ground.db.query(sql, [user_id, password])
			.then(()=> {
				return {
					password: password
				}
			})
	}

	static create_session(user, req, ground):Promise {
		var ip = req.headers['x-forwarded-for'] ||
			req.connection.remoteAddress ||
			req.socket.remoteAddress

		if (!ip && req.connection.socket)
			ip = req.connection.socket.remoteAddress

		var session = [
			user.id,
			req.sessionID,
			ip,
			Math.round(new Date().getTime() / 1000)
		]

		return ground.db.query("REPLACE INTO sessions (user, token, hostname, timestamp) VALUES (?, ?, ?, ?)", session)
			.then(() => session)
	}

	add_service(definition:Service_Definition) {
		this.services.push(definition)
	}

	private create_service(service:Service_Definition) {
		var http_path = service.http_path[0] != '/'
			? '/' + service.http_path
			: service.http_path

		this.app.post(http_path, (req, res)=> {
				var user = null
				// Start with a promise so all possible errors (short of one inside when.js) are
				// handled through promise rejections.  Otherwise we would need a try/catch here
				// and redundant error handling.
				when.resolve()
					.then(()=> this.get_user_from_session(req.sessionID))
					.then((u)=> {
						user = u
						return this.run_service(service, req.body, user, req)
					})
					.done((response)=> {
						res.send(response)
					}, (error)=> {
						var response = this.process_error(error, user)
						var status = response.status
						delete response.status
						res.status(status).json(response)
					})
			}
		)
	}

	private run_service(service, body, user, req):Promise {
		var pipeline:any = require('when/pipeline')
		return pipeline([
			()=> this.check_service(body, user, service.authorization, service.validation),
			()=> service.action(body, user, req)
		])
	}

	private create_socket_service(socket, user, service:Service_Definition) {
		socket.on(service.socket_path, (body, callback)=>
				this.run_service(service, body, user, null)
					.done((response)=> {
						if (callback)
							callback(response)
					}, (error)=> {
						error = error || {}
						console.log('socket error with path ' + service.socket_path + ':', error.message, error.status, error.stack)
						console.log(JSON.stringify(body))
						var status = error.status || 500

						var response = {
							status: status,
							request: body,
							message: status == 500 ? "Server Error" : error.message,
							key: error.key || 'unknown'
						}

						socket.emit('error', response)
					})
		)
	}

	check_service(data, user, authorization:(user, fortress)=>any, validation:string):Promise {
		if (authorization != null) {
			var fortress = this.vineyard.bulbs.fortress
			var access = authorization(user, fortress)
			if (!access)
				throw new Authorization_Error('Unauthorized', user)
		}

		if (validation) {
			var error = this.vineyard.find_schema_errors(data, validation)
			if (error) {
				var message = null
				if (error.code == 303) {
					message = "Unsupported property: " + error.dataPath.substring(1)
				}
				else {
					message = error.dataPath == ""
						? error.message
						: error.message + " for " + error.dataPath.substring(1)
				}

				throw new HttpError(message, 400, 'invalid-structure')
			}
		}

		return when.resolve()
	}

	send_http_login_success(req, res, user, query_arguments = null) {
		var query = this.ground.create_query('user')
		query.add_key_filter(user.id)
		var run_query = ()=> query.run_single(user)
			.then((row)=> {
				res.send({
					token: req.sessionID,
					message: 'Login successful',
					user: Lawn.format_internal_user(row)
				})
				console.log('sent-login-success', user.username)
			})

		if (query_arguments && (query_arguments.properties || query_arguments.expansions)) {
			if (query_arguments.properties)
				query.add_properties(query_arguments.properties)

			if (MetaHub.is_array(query_arguments.expansions))
				query.add_expansions(query_arguments.expansions)

			var fortress = this.vineyard.bulbs.fortress
			return fortress.query_access(user, query).then((result)=> {
				if (result.is_allowed) {
					result.secure_query(query)
					return run_query()
				}
				else {
					var sql = "DELETE FROM sessions WHERE user = ? AND token = ?";
					return this.ground.db.query(sql, [user.id, req.sessionID])
						.then(()=> {
							throw new Authorization_Error(result.get_message(), user)
						})
				}
			})
		} else {
			return run_query();
		}
	}


	register(req, res):Promise {
		var body = <User_Source>req.body,
			username = body.username,
			email = body.email,
			password = body.password,
			phone = body.phone,
			facebook_token = body.facebook_token,
			display_name = body[this.config.display_name_key]

		console.log('register', body)

		if (typeof username != 'string' || username.length > 32 || !username.match(this.config.valid_username))
			return when.reject(new HttpError('Invalid username.', 400))

		if (email && (!email.match(/\S+@\S+\.\S/) || email.match(/['"]/)))
			return when.reject(new HttpError('Invalid email address.', 400))

		if (!facebook_token) {
			if (typeof password != 'string' || password.length > 32 || !password.match(this.config.valid_password))
				return when.reject(new HttpError('Invalid password.', 400))
		}

		if (typeof display_name != 'string')
			display_name = null
		else if (!display_name.match(this.config.valid_display_name))
			return when.reject(new HttpError("Invalid " + this.config.display_name_key, 400))

		var register = (facebook_id = undefined)=> {
			var args = [body.username]
			var sql = "SELECT 'username' as value FROM users WHERE username = ?"
			if (body.email) {
				sql += "\nUNION SELECT 'email' as value FROM users WHERE email = ?"
				args.push(body.email)
			}

			if (facebook_id) {
				sql += "\nUNION SELECT 'facebook_id' as value FROM users WHERE facebook_id = ?"
				args.push(facebook_id)
			}

			return this.ground.db.query(sql, args)
				.then((rows)=> {
					if (rows.length > 0)
						return when.reject(new HttpError('That ' + rows[0].value + ' is already taken.', 400))

					var user = {};
					var trellis = this.ground.trellises['user']
					var properties = trellis.get_all_properties()
					for (var i in properties) {
						var property = properties[i]
						//console.log(property.name, property == trellis.primary_key || property.other_trellis != null, body[property.name]);
						if (property == trellis.primary_key)
							continue

						if (body[property.name] !== undefined && typeof body[property.name] !== 'object')
							user[property.name] = body[property.name]
					}
					user['roles'] = [2];

					//var user = {
					//  username: username,
					//  email: email,
					//  password: body.password,
					//  gender: gender,
					//  phone: phone,
					//  roles: [2],
					//  address: body.address,
					//  image: body.image
					//}
					//user[this.config.display_name_key] = display_name

					console.log('user', user, facebook_id)
					this.ground.create_update('user', user).run()
						.then((user)=> {
							var finished = ()=> {
								user.facebook_id = facebook_id
								res.send({
									message: 'User ' + username + ' created successfully.',
									user: user
								})
							}
							if (facebook_id)
								return this.ground.db.query_single("UPDATE users SET facebook_id = ? WHERE id = ?", [facebook_id, user.id])
									.then(finished)

							finished()
						})
				})
		}

		if (facebook_token !== undefined) {
			return this.vineyard.bulbs.facebook.get_user_facebook_id(body)
				.then((facebook_id)=> register(facebook_id))
		}
		else {
			return register()
		}
	}

	link_facebook_user(req, res, user):Promise {
		var body = req.body
		if (body.facebook_token === null || body.facebook_token === '') {
//      if (!user.facebook_id) {
//        res.send({
//          message: "Your account is already not linked to a facebook account.",
//          user: user
//        });
//        return when.resolve()
//      }

			console.log('connect-fb-user-detach', user)
			delete user.facebook_id
			return this.ground.db.query_single("UPDATE users SET facebook_id = NULL WHERE id = ?", [user.id])
				.then(()=> {
					res.send({
						message: 'Your user accont and facebook account are now detached.',
						user: user
					});
				})
		}
		return this.vineyard.bulbs.facebook.get_user_facebook_id(body)
			.then((facebook_id)=> {
				var args = [body.username]
				var sql = "SELECT 'username' as value, FROM users WHERE username = ?"
				if (body.email) {
					sql += "UNION SELECT 'email' as value FROM users WHERE email = ?"
					args.push(body.email)
				}

				if (facebook_id) {
					sql += "UNION SELECT 'facebook_id' as value FROM users WHERE facebook_id = ?"
					args.push(facebook_id)
				}

//        return this.ground.db.query_single("SELECT id, name FROM users WHERE facebook_id = ?", [facebook_id])
//          .then((row)=> {
//            if (row)
//              return when.reject(new HttpError('That facebook id is already attached to a user.', 400))

				console.log('connect-fb-user', {
					id: user.id,
					facebook_id: facebook_id,
				})
				return this.ground.db.query_single("UPDATE users SET facebook_id = NULL WHERE facebook_id = ?", [facebook_id])
					.then(()=> this.ground.db.query_single("UPDATE users SET facebook_id = ? WHERE id = ?", [facebook_id, user.id]))
					.then(()=> {
						user.facebook_id = facebook_id
						res.send({
							message: 'Your user accont is now attached to your facebook account.',
							user: user
						});
					})
//          })
			})
	}

	static request(options, data = null, secure = false):Promise {
		var def = when.defer()
		var http = require(secure ? 'https' : 'http')
//    if (secure)
//      options.secureProtocol = 'SSLv3_method'

		var req = http.request(options, function (res) {
			res.setEncoding('utf8')
			if (res.statusCode != '200') {
				res.on('data', function (chunk) {
					console.log('client received an error:', res.statusCode, chunk)
					def.reject()
				})
			}
			else {
				res.on('data', function (data) {
					if (res.headers['content-type'] &&
						(res.headers['content-type'].indexOf('json') > -1
						|| res.headers['content-type'].indexOf('javascript') > -1))
						res.content = JSON.parse(data)
					else
						res.content = data

					def.resolve(res)
				})
			}
		})

		if (data)
			req.write(JSON.stringify(data))

		req.end()

		req.on('error', function (e) {
			console.log('problem with request: ' + e.message);
			def.reject()
		})

		return def.promise
	}

	login(data, socket:ISocket, callback) {
		console.log('message2', data);
		if (!data.token) {
			socket.emit('error', {message: 'Missing token.'})
		}

		var query = this.ground.create_query('session')
		query.add_key_filter(data.token)

		this.get_user_from_session(data.token)
			.then((user)=> {
				this.initialize_session(socket, user);
				console.log('user', user)
				if (callback) {
					console.log('login callback called')
					callback(user)
				}
			},
			(error)=> {
				console.log('error', error.message, error.stack)

				socket.emit('socket login error', {
					'message': error.status == 500 || !error.message ? 'Error getting session.' : error.message
				})
			}
		).done()

	}

	on_connection(socket:ISocket) {
		console.log('connection attempted')
		socket.on('login', (data, callback)=> this.login(data, socket, callback));

		socket.emit('connection');
		return socket.on('disconnect', () => {
			var data, user;
			user = socket.user;
			if (user)
				delete this.instance_user_sockets[user.id][socket.id]

			delete this.instance_sockets[socket.id];
			if (user && !this.user_is_online(user.id)) {
				data = user
				if (this.ground.db.active)
					return this.ground.db.query('UPDATE users SET online = 0 WHERE id = ' + user.id)
//        data.online = false;
//        return Server.notify.send_online_changed(user, false);
			}

			return when.resolve()
		});
	}

	static
	process_public_http(req, res, action) {
		action(req, res)
			.done(()=> {
			}, (error)=> {
				error = error || {}
				var status = error.status || 500
				var message = status == 500 ? 'Server Error' : error.message
				if (status == 500)
					console.error('public http error:', status, error.message, error.stack || '')
				else
					console.log('public http error:', status, error.message, error.stack || '')
				res.status(status).json({message: message})
			})
	}

	on_socket(socket, event, user, action) {
		socket.on(event, (request, callback)=> {
			callback = callback || function () {
			}
			try {
				var promise = action(request)
				if (promise && typeof promise.done == 'function') {
					promise.done((response)=> {
							response = response || {}
							response.status = response.status || 200
							callback(response)
						},
						(error)=> callback(this.process_error(error, user))
					)
				}
				else {
					callback({status: 200})
				}
			}
			catch (err) {
				callback(this.process_error(err, user))
			}
		})
	}

	static
	listen_public_http(app, path, action, method = 'post') {
		app[method](path, (req, res)=>
				Lawn.process_public_http(req, res, action)
		)
	}

	listen_public_http(path, action, method = 'post') {
		this.app[method](path, (req, res)=>
				Lawn.process_public_http(req, res, action)
		)
	}


	process_error(error, user) {
		var status = error.status || 500
		var message = status == 500 ? 'Server Error' : error.message

		var response = {
			status: status,
			message: message,
			key: error.key || 'unknown'
		}

		var fortress = this.vineyard.bulbs.fortress
		if (user && fortress && fortress.user_has_role(user, 'dev')) {
			response.message = error.message || "Server Error"
			response['stack'] = error.stack
			response['details'] = error.details
		}

		if (this.config.log_authorization_errors !== false || status != 403)
			console.log('service error:', status, error.message, error.stack, error.key)

		return response
	}

	process_user_http(req, res, action) {
		var user = null, send_error = (error)=> {
			var response = this.process_error(error, user)
			var status = response.status
			delete response.status
			res.status(status).json(response)
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
//        console.log('server recieved query request.')
				this.process_user_http(req, res, action)
			}
		)
	}

	start_sockets(port = null) {
		var socket_io = require('socket.io')
		port = port || this.config.ports.websocket
		console.log('Starting Socket.IO on port ' + port)

		var io = this.io = socket_io.listen(port)
		io.set('log level', process.argv.indexOf('--monitor-sockets') > -1 ? 3 : 1);
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
			var RedisStore = require('socket.io/lib/stores/redis'), redis = require("socket.io/node_modules/redis"), pub = redis.createClient(), sub = redis.createClient(), client = redis.createClient()

			io.set('store', new RedisStore({
				redisPub: pub, redisSub: sub, redisClient: client
			}))
		}
	}

	file_download(req, res, user) {
		var guid = req.params.guid;
		var ext = req.params.ext;
		if (!guid.match(/[\w\-]+/) || !ext.match(/\w+/))
			throw new HttpError('Invalid File Name', 400)

		var path = require('path')
		var filepath = path.join(this.vineyard.root_path, this.config.file_path || 'files', guid + '.' + ext)
		console.log(filepath)
		return Lawn.file_exists(filepath)
			.then((exists)=> {
				if (!exists)
					throw new HttpError('File Not Found', 404)
//          throw new Error('File Not Found')

				var query = this.ground.create_query('file')
				query.add_key_filter(req.params.guid)
				var fortress = this.vineyard.bulbs.fortress

				fortress.query_access(user, query)
					.then((result)=> {
						if (result.access)
							res.sendfile(filepath)
						else
							throw new Authorization_Error('Access Denied', user)
					})
			})
	}

	private static
	file_exists(filepath:string):Promise {
		var fs = require('fs'), def = when.defer()
		fs.exists(filepath, (exists)=> {
			def.resolve(exists)
		})
		return def.promise
	}

	start_http(port) {
		if (!port)
			return

		if (typeof this.config.max_connections == 'number') {
			var http = require('http')
			http.globalAgent.maxSockets = this.config.max_connections
		}

		var express = require('express');
		var app = this.app = express();

		//app.use(require('body-parser')({keepExtensions: true, uploadDir: "tmp"}));
		var parser = require('body-parser')
		app.use(parser.json())
		app.use(require('cookie-parser')());

		var session:any = require('express-session')
		if (typeof this.config.mysql_session_store == 'object') {
			var MySQL_Session_Store = require('express-mysql-session')
			var storage_config = <Lawn.Session_Store_Config>this.config.mysql_session_store

			console.log('using mysql sessions store: ', storage_config.db)

			app.use(session({
				key: storage_config.key,
				secret: storage_config.secret,
				resave: true,
				saveUninitialized: true,
				store: new MySQL_Session_Store(storage_config.db)
			}))
		}
		else {
			if (!this.config.cookie_secret)
				throw new Error('lawn.cookie_secret must be set!')

			app.use(session({
				secret: this.config.cookie_secret, resave: true,
				saveUninitialized: true
			}))
		}

		if (this.config.allow_cors === true) {
			app.use(require('cors')())
			console.log('Using CORS')
		}

		// Log request info to a file
		if (typeof this.config.log_file === 'string') {
			var fs = require('fs')
			var log_file = fs.createWriteStream(this.config.log_file, {flags: 'a'})
			app.use(express.logger({stream: log_file}))
		}

		// Hook login and logout for both GET and POST
		this.listen_public_http('/vineyard/login', (req, res)=> this.http_login(req, res, req.body))
		this.listen_public_http('/vineyard/login', (req, res)=> this.http_login(req, res, req.query), 'get')
		this.listen_user_http('/vineyard/logout', (req, res, user)=> this.logout(req, res, user))
		this.listen_user_http('/vineyard/logout', (req, res, user)=> this.logout(req, res, user), 'get')

		if (this.config.allow_register)
			this.listen_public_http('/vineyard/register', (req, res)=> this.register(req, res))

		for (var i in this.services) {
			var service = this.services[i]
			if (service.http_path)
				this.create_service(service)
		}

		this.listen_public_http('/vineyard/password-reset', (req, res)=> this.password_reset_request(req, res, req.body))
		this.listen_user_http('/vineyard/current-user', (req, res, user)=> {
			res.send({
				status: 200,
				user: Lawn.format_public_user(user)
			})
			return when.resolve()
		}, 'get')

		this.listen_user_http('/vineyard/upload', (req, res, user)=> {
			console.log('files', req.files)
			console.log('req.body', req.body)
			var info = JSON.parse(req.body.info)
			var file = req.files.file;
			var guid = info.guid;
			if (!guid)
				throw new HttpError('guid is empty.', 400)

			if (!guid.match(/[\w\-]+/))
				throw new HttpError('Invalid guid.', 400)

			var path = require('path')
			var ext = path.extname(file.originalFilename) || ''
			var filename = guid + ext
			var filepath = (this.config.file_path || 'files') + '/' + filename
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

//    this.listen_public_http('/vineyard/register', (req, res)=> this.register(req, res))
		this.listen_user_http('/file/:guid.:ext', (req, res, user)=> this.file_download(req, res, user), 'get')
		this.listen_user_http('/vineyard/facebook/link', (req, res, user)=> this.link_facebook_user(req, res, user), 'post')
		this.listen_user_http('/vineyard/schema', (req, res, user)=> this.get_schema(req, res, user), 'get')

		app.use(function (err, req, res, next) {
			console.log('e')
			console.error(err.stack)
			if (err && err.name == 'SyntaxError') {
				res.status(400).json({
					message: 'Invalid JSON',
					key: 'invalid-json'
				})
			}
			next(err)
		})

		port = port || this.config.ports.http
		console.log('HTTP listening on port ' + port + '.')

		this.invoke('http.start', app, this)
		this.http = app.listen(port)
	}

	stop() {
		console.log('Stopping Lawn')
		if (this.io && this.io.server) {
			console.log('Stopping Socket.IO')
			var clients = this.io.sockets.clients()
			for (var i in clients) {
				clients[i].disconnect()
			}
			this.io.server.close()
			this.io = null
		}

		if (this.redis_client) {
			this.redis_client.quit()
			this.redis_client = null
		}

		if (this.http) {
			console.log('Closing HTTP.')
			this.http.close()
			this.http = null
			this.app = null
		}

		console.log('Lawn is stopped.')
	}

	public user_is_online(id:number) {
		if (!this.io)
			return false

		var room = this.io.sockets.clients(id)
		return room && room.length > 0
	}
}

module Lawn {

	export interface Mail_Config {
		transport:Mail_Transport_Config
		address:string
	}

	export interface Mail_Transport_Config {

	}

	export interface Session_Store_DB {
		host:string
		port:number
		user:string
		password:string
		database:string
	}

	export interface Session_Store_Config {
		key:string
		secret:string
		db: Session_Store_DB
	}

	export interface Config {
		ports
		log_updates?:boolean
		use_redis?:boolean
		cookie_secret?:string
		log_file?:string
		admin
		file_path?:string
		mysql_session_store?:Session_Store_Config
		mail?:Mail_Config
		password_reset_template?:string
		site
		display_name_key:string
		log_authorization_errors?:boolean
		valid_username?
		valid_display_name?
		valid_password?
		allow_cors?:boolean
		allow_register?:boolean
		max_connections?:number
	}

	export class Facebook extends Vineyard.Bulb {
		lawn:Lawn

		grow() {
			this.lawn = this.vineyard.bulbs.lawn
		}

		create_user(facebook_id, source):Promise {
			var user = {
				username: source.username,
				email: source.email,
				gender: source.gender,
				facebook_id: facebook_id
			}
			user[this.lawn.config.display_name_key] = source.name

			console.log('user', user)
			return this.ground.create_update('user', user).run()
				.then((user)=> {
					var result = {
						id: user.id,
						username: user.username
					}
					result[this.lawn.config.display_name_key] = user.name
					return result
				})
		}

		login(req, res, body):Promise {
			console.log('facebook-login', body)

			return this.get_user(body)
				.then((user)=> {
					return Lawn.create_session(user, req, this.ground)
						.then(()=> this.vineyard.bulbs.lawn.send_http_login_success(req, res, user))
				})
		}

		get_user(body):Promise {
			return this.get_user_facebook_id(body)
				.then((facebook_id)=> {
					console.log('fb-user', facebook_id)
					if (!facebook_id) {
						return when.resolve(new HttpError('Invalid facebook login info.', 400))
					}

					return this.ground.db.query_single("SELECT id, username FROM users WHERE facebook_id = ?", [facebook_id])
						.then((user)=> {
							if (user)
								return user

							throw new HttpError('That Facebook user id is not yet connected to an account.  Redirect to registration.', 300)
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
						})
				})
		}

		get_user_facebook_id(body):Promise {
			if (typeof body.facebook_token != 'string' && typeof body.facebook_token != 'number')
				throw new HttpError('Requires either valid facebook user id or email address.', 400)

			var options = {
				host: 'graph.facebook.com',
				path: '/oauth/access_token?'
				+ 'client_id=' + this.config['app'].id
				+ '&client_secret=' + this.config['app'].secret
				+ '&grant_type=client_credentials',
				method: 'GET'
			}

			return Lawn.request(options, null, true)
				.then((response) => {
					var url = require('url')
					var info = url.parse('temp.com?' + response.content, true)
					var access_token = info.query.access_token

					var post = {
						host: 'graph.facebook.com',
						path: '/debug_token?'
						+ 'input_token=' + body.facebook_token
						+ '&access_token=' + access_token,
						method: 'GET'
					}

					return Lawn.request(post, null, true)
				})
				.then((response) => {
					console.log('facebook-check', response.content)
					return response.content.data.user_id
				})
		}
	}

	export class Mail {
		transporter
		config:Mail_Config

		constructor(config:Mail_Config) {
			this.config = config
			var nodemailer = require('nodemailer')
			var ses_transport = require('nodemailer-ses-transport')
			this.transporter = nodemailer.createTransport(ses_transport(config))
		}

		send(to, subject:string, text:string):Promise {
//    console.log('Sending email to ', to)
			var def = when.defer()
			console.log(this.config.address)
			this.transporter.sendMail({
				from: this.config.address,
				to: to,
				subject: subject,
				html: text
			}, function (error, info) {
				if (error) {
					console.log('error', error)
					def.reject(error)
				}
				else {
					def.resolve(info)
					console.log('info', info)
				}
			})

			return def.promise
		}
	}

	export var HttpError
	export var Irrigation
}
Lawn.HttpError = HttpError
Lawn.Irrigation = Irrigation