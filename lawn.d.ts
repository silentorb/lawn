/// <reference path="socket.io.extension.d.ts" />


/// <reference path="metahub.d.ts" />
/// <reference path="ground.d.ts" />
/// <reference path="vineyard.d.ts" />
declare class Lawn extends Vineyard.Bulb {
    public io;
    public instance_sockets: {};
    public instance_user_sockets: {};
    private app;
    public fs;
    public config;
    public redis_client;
    static authorization(handshakeData, callback);
    public debug(...args: any[]): void;
    public get_user_socket(id: number): Socket;
    public initialize_session(socket, user): void;
    public start(): void;
    public login(data, socket: ISocket, callback): {};
    public on_connection(socket: ISocket): Socket;
    public start_sockets(port?): void;
    public start_http(port): void;
    public stop(): void;
}
declare module Lawn {
    interface IUser {
        id?;
        name?: string;
    }
    class User {
        public id: number;
        public name: string;
        public session;
        constructor(source: IUser);
        public simple(): IUser;
    }
}
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