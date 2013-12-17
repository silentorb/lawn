/// <reference path="../defs/socket.io.extension.d.ts" />
/// <reference path="../defs/express.d.ts" />
/// <reference path="../lawn.d.ts" />
export declare class Lawn extends Vineyard.Bulb {
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
