/// <reference path="../../vineyard/vineyard.d.ts" />
export declare class HttpError {
    public name: string;
    public message: any;
    public stack: any;
    public status: any;
    public details: any;
    public key: any;
    constructor(message: string, status?: number, key?: any);
}
export declare class Authorization_Error extends HttpError {
    constructor(message: string);
}
export declare function is_authenticated(user: any, fortress: any): boolean;
export declare function is_admin(user: any, fortress: any): any;
export interface Update_Request {
    objects: any[];
    version?: number;
}
export interface Service_Definition {
    http_path: string;
    socket_path: string;
    authorization: (user: any, fortress: any) => any;
    validation: string;
    action: (data: any, user: any) => Promise;
}
