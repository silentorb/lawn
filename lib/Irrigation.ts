/**
 * User: Chris Johnson
 * Date: 10/3/13
 */
/// <reference path="references.ts"/>

module Lawn {

  export interface Query_Request {
    trellis:string;
    filters?:Ground.Query_Filter[]
    sorts?:Ground.Query_Sort[]
    expansions?:string[]
    reductions?:string[]
  }

  export interface Update_Request {
    objects:any[];
  }

  export class Irrigation {
    static query(request:Query_Request, user:Vineyard.IUser, ground:Ground.Core, vineyard:Vineyard):Promise {
      var i, trellis = ground.sanitize_trellis_argument(request.trellis);
      var query = new Ground.Query(trellis);

      if (request.filters) {
        for (i = 0; i < request.filters.length; ++i) {
          var filter = request.filters[i]
          query.add_property_filter(filter.property, filter.value, filter.operator)
        }
      }

      if (request.sorts) {
        for (i = 0; i < request.sorts.length; ++i) {
          query.add_sort(request.sorts[i])
        }
      }

      if (request.expansions) {
        for (i = 0; i < request.expansions.length; ++i) {
          query.expansions.push(request.expansions[i])
        }
      }

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