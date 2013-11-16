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
    static query(request:Query_Request, ground:Ground.Core, vineyard:Vineyard):Promise {
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

      if (vineyard) {
        var fortress = vineyard.bulbs.fortress
        return fortress.query_access(query)
          .then((access)=> {
            if (access)
              return query.run();
            else
              return when.resolve([])
          }
      }

      return query.run();
    }

    static update(request:Update_Request, uid, ground:Ground.Core, vineyard:Vineyard):Promise {
      var promises:Promise[] = [];

      if (!request.objects)
        throw new Error('Request requires an objects array.');

      for (var i = 0; i < request.objects.length; ++i) {
        var object = request.objects[i];
        var promise = ground.update_object(object.trellis, object, uid);
        promises.push(promise);
      }

      return when.all(promises)
    }
  }
}