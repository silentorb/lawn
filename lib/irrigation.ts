/// <reference path="references.ts"/>

class Irrigation {

  static query(request:mining.External_Query_Source, user:Vineyard.IUser, lawn):Promise {
    var ground:Ground.Core = lawn.ground, vineyard:Vineyard = lawn.vineyard
    var Fortress = require('vineyard-fortress')
    if (vineyard.bulbs['lawn'].config.require_version === true && !request.version)
      throw new HttpError('The request must have a version property.', 400, 'version-required')

    if (!request)
      throw new HttpError('Empty request', 400)

    if (!ground.schema.trellises[request.trellis])
      throw new HttpError('Invalid trellis: ' + request.trellis + '.', 400, 'invalid-trellis')

    var trellis = ground.sanitize_trellis_argument(request.trellis)
    var query = lawn.ground.create_query(trellis)

    Irrigation.inject_user(request, user)

    query.extend(request)

    var fortress = vineyard.bulbs.fortress
    return fortress.query_access(user, query)
      .then((result)=> {
        //console.log('fortress', result)
        if (result.is_allowed) {
          result.secure_query(query)
          return Irrigation.run_query(query, user, vineyard, request)
        }
        else {
          throw new Authorization_Error(result.get_message(), user)
        }
      })
  }

  static inject_user(query:mining.External_Query_Source, user:Vineyard.IUser) {
    if (query.filters) {
      for (var i = 0; i < query.filters.length; ++i) {
        var filter = query.filters[i]
        if (filter.type == 'parameter' && filter.value == 'user') {
          filter.value = user.id
        }
      }
    }
  }

  static run_query(query:mining.Query_Builder, user:Vineyard.IUser, vineyard:Vineyard, request:mining.External_Query_Source):Promise {
    var lawn = vineyard.bulbs['lawn']
    var query_result:mining.Query_Result = {query_count: 0, user: user}
    var fortress = vineyard.bulbs.fortress
    if (request.return_sql === true && (!fortress || fortress.user_has_role(user, 'dev')))
      query_result.return_sql = true;

    var start = Date.now()
    return query.run(user, vineyard.ground.miner, query_result)
      .then((result)=> {
        result.query_stats.duration = Math.abs(Date.now() - start)
        if (result.sql && !vineyard.ground.log_queries)
          console.log('\nservice-query:', "\n" + result.sql)

        if (result.total === undefined)
          result.total = result.objects.length

        if (lawn.config.log_queries === true) {
          var sql = "INSERT INTO query_log (user, trellis, timestamp, request, duration, query_count, object_count, version)"
            + " VALUES (?, ?, UNIX_TIMESTAMP(), ?, ?, ?, ?, ?)"

          // This may cause some problems with the automated tests,
          // but the response does not wait for this log to be stored.
          // I'm doing it this way because the whole point of this log is performance timing
          // and I don't want it to bloat the perceived external request time.
            vineyard.ground.db.query(sql, [
            user.id,
            query.trellis.name,
            JSON.stringify(request),
            result.query_stats.duration,
            result.query_stats.count,
            result.objects.length,
            request.version || lawn.config.default_version || "?"
          ])
        }
        return result
      })
  }

  static update2(request:Update_Request, user, lawn):Promise {
    var ground:Ground.Core = lawn.ground, vineyard:Vineyard = lawn.vineyard
    if (vineyard.bulbs['lawn'].config.require_version === true && !request.version)
      throw new HttpError('The request must have a version property.', 400, 'version-required')

    var updates = request.objects.map((object)=>
        ground.create_update(object.trellis, object, user)
    )

    var fortress = vineyard.bulbs.fortress
    return fortress.update_access(user, updates)
      .then((result)=> {
        if (result.is_allowed) {
          var update_promises = updates.map((update) => update.run())
          return when.all(update_promises)
            .then((objects)=> {
              return {
                objects: objects
              }
            })
        }
        else {
          throw new Authorization_Error(result.get_message(), user)
        }
      })
  }

  static grow(lawn) {
    lawn.vineyard.add_json_schema('ground-query', lawn.ground.query_schema)
    lawn.vineyard.add_json_schema('ground-update', lawn.ground.update_schema)
    lawn.add_service({
      http_path: 'vineyard/query',
      socket_path: 'query',
      //authorization: is_authenticated,
      validation: 'ground-query',
      action: (data, user)=> Irrigation.query(data, user, lawn)
    })

    lawn.add_service({
      http_path: 'vineyard/update',
      socket_path: 'update',
      //authorization: is_authenticated,
      validation: 'ground-update',
      action: (data, user)=> Irrigation.update2(data, user, lawn)
    })
  }
}
