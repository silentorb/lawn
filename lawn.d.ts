/// <reference path="socket.io.extension.d.ts" />

/// <reference path="metahub.d.ts" />
/// <reference path="ground.d.ts" />
/// <reference path="vineyard.d.ts" />

declare var Irrigation: any;
declare module Lawn {
    interface Config {
        ports: any;
        log_updates?: boolean;
        use_redis?: boolean;
        cookie_secret?: string;
        log_file?: string;
    }
}
declare class Lawn extends Vineyard.Bulb {
    public io: any;
    public instance_sockets: {};
    public instance_user_sockets: {};
    private app;
    public fs: any;
    public config: Lawn.Config;
    public redis_client: any;
    public http: any;
    public grow(): void;
    static authorization(handshakeData: any, callback: any): any;
    public debug(...args: any[]): void;
    public get_user_socket(id: number): Socket;
    public initialize_session(socket: any, user: any): void;
    public start(): void;
    public get_user_from_session(token: string): Promise;
    public http_login(req: any, res: any, body: any): void;
    public login(data: any, socket: ISocket, callback: any): {};
    public on_connection(socket: ISocket): Socket;
    public start_sockets(port?: any): void;
    public start_http(port: any): void;
    public stop(): void;
}
declare module Lawn {
    interface Update_Request {
        objects: any[];
    }
    class Irrigation {
        static process(method: string, request: Ground.External_Query_Source, user: Vineyard.IUser, vineyard: Vineyard, socket: any, callback: any): Promise;
        static query(request: Ground.External_Query_Source, user: Vineyard.IUser, ground: Ground.Core, vineyard: Vineyard): Promise;
        static update(request: Update_Request, user: Vineyard.IUser, ground: Ground.Core, vineyard: Vineyard): Promise;
    }
}
declare module "lawn" {
  export = Lawn
}