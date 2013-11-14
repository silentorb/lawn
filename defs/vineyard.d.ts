/// <reference path="ground.d.ts" />
/// <reference path="metahub.d.ts" />
declare class Vineyard {
    public bulbs: any;
    public config;
    public config_folder;
    public ground: Ground.Core;
    constructor(config_file?: string);
    static create_ground(db_name: string, databases, trellis_files): Ground.Core;
    public get_bulb(name: string): Promise;
    public load_bulbs(bulbs): void;
    public load(config_file: string): void;
    public start(): void;
}
declare module Vineyard {
    class Bulb extends MetaHub.Meta_Object {
        public vineyard: Vineyard;
        public config;
        public ground: Ground.Core;
        constructor(vineyard: Vineyard, config);
        public grow(): void;
        public start(): void;
        public stop(): void;
    }
}
declare module "vineyard" {
  export = Vineyard
}