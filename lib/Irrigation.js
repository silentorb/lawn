/**
* User: Chris Johnson
* Date: 10/3/13
*/
/// <reference path="references.ts"/>
var Lawn;
(function (Lawn) {
    var Irrigation = (function () {
        function Irrigation() {
        }
        Irrigation.query = function (request, ground, vineyard) {
            var i, trellis = ground.sanitize_trellis_argument(request.trellis);
            var query = new Ground.Query(trellis);

            if (request.filters) {
                for (i = 0; i < request.filters.length; ++i) {
                    var filter = request.filters[i];
                    query.add_property_filter(filter.property, filter.value, filter.operator);
                }
            }

            if (request.sorts) {
                for (i = 0; i < request.sorts.length; ++i) {
                    query.add_sort(request.sorts[i]);
                }
            }

            if (request.expansions) {
                for (i = 0; i < request.expansions.length; ++i) {
                    query.expansions.push(request.expansions[i]);
                }
            }

            if (vineyard) {
                var fortress = vineyard.bulbs.fortress;
                if (!fortress.query_access(query)) {
                    return when.resolve([]);
                }
            }
            return query.run();
        };

        Irrigation.update = function (request, uid, ground, vineyard) {
            var promises = [];

            if (!request.objects)
                throw new Error('Request requires an objects array.');

            for (var i = 0; i < request.objects.length; ++i) {
                var object = request.objects[i];
                var promise = ground.update_object(object.trellis, object, uid);
                promises.push(promise);
            }

            return when.all(promises);
        };
        return Irrigation;
    })();
    Lawn.Irrigation = Irrigation;
})(Lawn || (Lawn = {}));
//# sourceMappingURL=Irrigation.js.map
