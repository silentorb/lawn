/// <reference path="common.ts"/>
var common = require('./common');
var Ground = require('vineyard-ground');
var MetaHub = require('vineyard-metahub');
var HttpError = common.HttpError;

function prepare_fortress(fortress, user) {
    if (!fortress)
        return when.resolve();

    return fortress.get_roles(user);
}

function process(method, request, user, vineyard, socket, callback) {
    var fortress = vineyard.bulbs.fortress;
    var action = method == 'query' ? query : exports.update;
    return prepare_fortress(fortress, user).then(function () {
        return action(request, user, vineyard.ground, vineyard);
    }).then(function (result) {
        result.status = 200;
        result.message = 'Success';
        if (callback)
            callback(result);
        else if (method != 'update')
            socket.emit('error', {
                status: 400,
                message: 'Query requests need to ask for an acknowledgement',
                request: request
            });
    }, function (error) {
        //          if (callback)
        //            callback({ code: 403, 'message': 'You are not authorized to perform this update.', objects: [],
        //              unauthorized_object: error.resource})
        //          else
        error = error || {};
        console.log(method + 'service error:', error.message, error.status, error.stack);
        console.log(JSON.stringify(request));
        var status = error.status || 500;

        var response = {
            code: status,
            status: status,
            request: request,
            message: status == 500 ? "Server Error" : error.message,
            key: error.key || 'unknown'
        };

        if (fortress.user_has_role(user, 'dev')) {
            response.message = error.message || "Server Error";
            response['stack'] = error.stack;
            details:
            error.details;
        }

        if (vineyard.bulbs.lawn.debug_mode)
            console.log('error', error.stack);

        if (callback)
            callback(response);
        else
            socket.emit('error', response);
    });
}
exports.process = process;

function query(request, user, lawn) {
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
    query.extend(request);

    var fortress = vineyard.bulbs.fortress;
    return fortress.query_access(user, query).then(function (result) {
        if (result.is_allowed)
            return run_query(query, user, vineyard, request);
        else {
            throw new common.Authorization_Error(result.get_message());
        }
    });
}

function run_query(query, user, vineyard, request) {
    var lawn = vineyard.bulbs['lawn'];
    var query_result = { query_count: 0 };
    var fortress = vineyard.bulbs.fortress;
    if (request.return_sql === true && (!fortress || fortress.user_has_role(user, 'dev')))
        query_result.return_sql = true;

    var start = Date.now();
    return query.run(query_result).then(function (result) {
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
}

function update(request, user, ground, vineyard) {
    if (vineyard.bulbs['lawn'].config.require_version === true && !request.version)
        throw new HttpError('The request must have a version property.', 400, 'version-required');

    if (user.id == 2)
        throw new HttpError('Anonymous cannot create content.', 403);

    if (!MetaHub.is_array(request.objects))
        throw new HttpError('Update is missing objects list.', 400);

    var updates = request.objects.map(function (object) {
        return ground.create_update(object.trellis, object, user);
    });

    if (!request.objects)
        throw new HttpError('Request requires an objects array', 400);

    var fortress = vineyard.bulbs.fortress;
    if (fortress) {
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
            } else
                throw new common.Authorization_Error('You are not authorized to perform this update');
        });
    } else {
        return when.all(updates.map(function (update) {
            return update.run();
        })).then(function (objects) {
            return {
                objects: objects
            };
        });
    }
}
exports.update = update;

function grow(lawn) {
    lawn.vineyard.add_json_schema('ground-query', lawn.ground.query_schema);
    lawn.add_service({
        http_path: 'vineyard/query',
        //socket_path: 'gardener/config',
        authorization: common.is_authenticated,
        validation: 'ground-query',
        action: function (data, user) {
            return query(data, user, lawn);
        }
    });
    //request:Ground.External_Query_Source, user:Vineyard.IUser, ground:Ground.Core, vineyard:Vineyard):Promis
    // lawn.listen_user_http('/vineyard/update', (req, res, user)=> {
    //   return update(req.body, user, lawn.ground, lawn.vineyard)
    //     .then((result)=> {
    //       if (!result.status)
    //         result.status = 200
    //
    //       result.message = 'Success'
    //       res.send(result)
    //     })
    // })
}
exports.grow = grow;
//# sourceMappingURL=irrigation.js.map
