/// <reference path="common.d.ts" />
import common = require('./common');
export declare function process(method: string, request: Ground.External_Query_Source, user: Vineyard.IUser, vineyard: Vineyard, socket: any, callback: any): Promise;
export declare function update(request: common.Update_Request, user: any, ground: Ground.Core, vineyard: Vineyard): Promise;
export declare function grow(lawn: any): void;
