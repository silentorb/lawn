/// <reference path="../vineyard/vineyard.d.ts" />
/// <reference path="defs/socket.io.extension.d.ts" />
/// <reference path="defs/express.d.ts" />
declare class HttpError {
    public name: string;
    public message: any;
    public stack: any;
    public status: any;
    public details: any;
    public key: any;
    constructor(message: string, status?: number, key?: any);
}
declare class Authorization_Error extends HttpError {
    constructor(message: string, user: any);
}
declare function is_authenticated(user: any, fortress: any): boolean;
declare function is_admin(user: any, fortress: any): any;
interface Update_Request {
    objects: any[];
    version?: number;
}
interface Service_Definition {
    http_path: string;
    socket_path: string;
    authorization: (user: any, fortress: any) => any;
    validation: string;
    action: (data: any, user: any) => Promise;
}
declare class Gardener {
    static set_config(data: any, lawn: any): any;
    static grow(lawn: any): void;
}
declare class Irrigation {
    static query(request: Ground.External_Query_Source, user: Vineyard.IUser, lawn: any): Promise;
    static run_query(query: Ground.Query_Builder, user: Vineyard.IUser, vineyard: Vineyard, request: Ground.External_Query_Source): Promise;
    static update2(request: Update_Request, user: any, lawn: any): Promise;
    static grow(lawn: any): void;
}
interface User_Source {
    name?: string;
    display_name?: string;
    username: string;
    password: string;
    email?: string;
    phone?: string;
    gender?: string;
    facebook_token?: string;
    image?: string;
    address?: any;
}
declare class Lawn extends Vineyard.Bulb {
    public io: any;
    public instance_sockets: {};
    public instance_user_sockets: {};
    public app: any;
    public config: Lawn.Config;
    public redis_client: any;
    public http: any;
    public debug_mode: boolean;
    public mail: Lawn.Mail;
    public password_reset_template: string;
    private services;
    public grow(): void;
    static authorization(handshakeData: any, callback: any): any;
    public emit_to_users(users: any, name: any, data: any): Promise;
    public notify(users: any, name: any, data: any, trellis_name: string): Promise;
    public get_user_sockets(id: number): Socket[];
    public initialize_session(socket: any, user: any): void;
    public query_user(user: any, query: Ground.Query_Builder): void;
    public start(): Promise;
    static public_user_properties: string[];
    static internal_user_properties: string[];
    private static is_ready_user_object(user);
    private static format_public_user(user);
    private static format_internal_user(user);
    public get_public_user(user: any): Promise;
    public get_schema(req: any, res: any, user: any): void;
    public get_user_from_session(token: string): Promise;
    public http_login(req: any, res: any, body: any): Promise;
    public logout(req: any, res: any, user: any): Promise;
    public is_configured_for_password_reset(): boolean;
    public check_password_reset_configuration(req: any, res: any, body: any): Promise;
    public password_reset_request(req: any, res: any, body: any): Promise;
    public create_password_reset_entry(user_id: any): Promise;
    static create_session(user: any, req: any, ground: any): Promise;
    public add_service(definition: Service_Definition): void;
    private create_service(service);
    private run_service(service, body, user, req);
    private create_socket_service(socket, user, service);
    public check_service(data: any, user: any, authorization: (user: any, fortress: any) => any, validation: string): Promise;
    public send_http_login_success(req: any, res: any, user: any, query_arguments?: any): any;
    public register(req: any, res: any): Promise;
    public link_facebook_user(req: any, res: any, user: any): Promise;
    static request(options: any, data?: any, secure?: boolean): Promise;
    public login(data: any, socket: ISocket, callback: any): void;
    public on_connection(socket: ISocket): Socket;
    static process_public_http(req: any, res: any, action: any): void;
    public on_socket(socket: any, event: any, user: any, action: any): void;
    static listen_public_http(app: any, path: any, action: any, method?: string): void;
    public listen_public_http(path: any, action: any, method?: string): void;
    public process_error(error: any, user: any): {
        status: any;
        message: any;
        key: any;
    };
    public process_user_http(req: any, res: any, action: any): void;
    public listen_user_http(path: any, action: any, method?: string): void;
    public start_sockets(port?: any): void;
    public file_download(req: any, res: any, user: any): Promise;
    private static file_exists(filepath);
    public start_http(port: any): void;
    public stop(): void;
    public user_is_online(id: number): boolean;
}
declare module Lawn {
    interface Mail_Config {
        transport: Mail_Transport_Config;
        address: string;
    }
    interface Mail_Transport_Config {
    }
    interface Session_Store_DB {
        host: string;
        port: number;
        user: string;
        password: string;
        database: string;
    }
    interface Session_Store_Config {
        key: string;
        secret: string;
        db: Session_Store_DB;
    }
    interface Config {
        ports: any;
        log_updates?: boolean;
        use_redis?: boolean;
        cookie_secret?: string;
        log_file?: string;
        admin: any;
        file_path?: string;
        mysql_session_store?: Session_Store_Config;
        mail?: Mail_Config;
        password_reset_template?: string;
        site: any;
        display_name_key: string;
        log_authorization_errors?: boolean;
        valid_username?: any;
        valid_display_name?: any;
        valid_password?: any;
        allow_cors?: boolean;
        allow_register?: boolean;
    }
    class Facebook extends Vineyard.Bulb {
        public lawn: Lawn;
        public grow(): void;
        public create_user(facebook_id: any, source: any): Promise;
        public login(req: any, res: any, body: any): Promise;
        public get_user(body: any): Promise;
        public get_user_facebook_id(body: any): Promise;
    }
    interface Songbird_Method {
        send: (user: any, message: string, data: any, badge: any) => Promise;
    }
    class Songbird extends Vineyard.Bulb {
        public lawn: Lawn;
        public fallback_bulbs: Songbird_Method[];
        public templates: any;
        public grow(): void;
        public initialize_socket(socket: any, user: any): void;
        public add_fallback(fallback: any): void;
        public format_message(name: any, data: any): string;
        public notify(users: any, name: any, data: any, trellis_name: string, store?: boolean): Promise;
        public notification_receieved(user: any, request: any): Promise;
        public send_pending_notifications(user: any): void;
    }
    class Mail {
        public transporter: any;
        public config: Mail_Config;
        constructor(config: Mail_Config);
        public send(to: any, subject: string, text: string): Promise;
    }
    var HttpError: any;
    var Irrigation: any;
}
declare function typescript_bulb_export_hack(): void;
