/**
 * User: Chris Johnson
 * Date: 10/3/13
 */
/// <reference path="references.ts"/>

module Lawn {

  export interface Update_Request {
    objects:any[];
  }

  export class Irrigation {
    static query(request:Ground.External_Query_Source, user:Vineyard.IUser, ground:Ground.Core, vineyard:Vineyard):Promise {
      if (!request)
        throw new Error('Empty request.')

      var trellis = ground.sanitize_trellis_argument(request.trellis);
      var query = new Ground.Query(trellis);

      query.extend(request)

      var fortress = vineyard.bulbs.fortress
      return fortress.query_access(user, query)
        .then((access)=> {
          if (access)
            return query.run();
          else
            throw new Error('Unauthorized')
        })
    }

    static update(request:Update_Request, user:Vineyard.IUser, ground:Ground.Core, vineyard:Vineyard):Promise {
      var updates = request.objects.map((object)=>
          ground.create_update(object.trellis, object, user)
      )

      if (!request.objects)
        throw new Error('Request requires an objects array.');

      var fortress = vineyard.bulbs.fortress
      return fortress.update_access(user, updates)
        .then((access)=> {
          if (access) {
            var update_promises = updates.map((update) => update.run())
            return when.all(update_promises)
          }
          else
            throw new Error('Unauthorized')
        })


    }
  }
}