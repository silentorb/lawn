/// <reference path="socket.io.extension.d.ts" />

/// <reference path="metahub.d.ts" />
/// <reference path="ground.d.ts" />
/// <reference path="vineyard.d.ts" />
declare module Lawn {
    interface Query_Request {
        trellis: string;
        filters?: Ground.Query_Filter[];
        sorts?: Ground.Query_Sort[];
        expansions?: string[];
        reductions?: string[];
    }
    interface Update_Request {
        objects: any[];
    }
    class Irrigation {
        static query(request: Query_Request, ground: Ground.Core, vineyard: Vineyard): Promise;
        static update(request: Update_Request, uid, ground: Ground.Core, vineyard: Vineyard): Promise;
    }
}
declare module "lawn" {
  export = Lawn
}