/**
* User: Chris Johnson
* Date: 11/15/2014
*/
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
export declare function is_admin(user: any, fortress: any): any;
