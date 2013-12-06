
/// <reference path="when.d.ts" />

/// <reference path="metahub.d.ts" />
declare var when;
declare module Ground {
    class Database {
        public settings: {};
        public database: string;
        public log_queries: boolean;
        constructor(settings: {}, database: string);
        public add_table_to_database(table: Ground.Table, ground: Ground.Core): Promise;
        public add_non_trellis_tables_to_database(tables: Ground.Table[], ground: Ground.Core): Promise;
        public create_table(trellis: Ground.Trellis): Promise;
        public create_trellis_tables(trellises: Ground.Trellis[]): Promise;
        public drop_all_tables(): Promise;
        public get_tables(): Promise;
        public query(sql: string, args?: any[]): Promise;
        public query_single(sql: string, args?: any[]): Promise;
    }
}
declare module Ground {
    interface ITrellis {
    }
    class Trellis implements ITrellis {
        public plural: string;
        public parent: Trellis;
        public ground: Ground.Core;
        public table: Ground.Table;
        public name: string;
        public primary_key: string;
        public properties: {
            [name: string]: Ground.Property;
        };
        public all_properties: {
            [name: string]: Ground.Property;
        };
        public is_virtual: boolean;
        constructor(name: string, ground: Ground.Core);
        public add_property(name: string, source): Ground.Property;
        public check_primary_key(): void;
        public clone_property(property_name: string, target_trellis: Trellis): void;
        public get_all_links(filter?: (property: Ground.Property) => boolean): {
            [name: string]: Ground.Property;
        };
        public get_all_properties(): {
            [name: string]: Ground.Property;
        };
        public get_core_properties(): {
            [name: string]: Ground.Property;
        };
        public get_id(source);
        public get_parent_join(main_table: string): string;
        public get_links(): Ground.Property[];
        public get_plural(): string;
        public get_primary_keys(): any[];
        public get_reference_property(other_trellis: Trellis): Ground.Property;
        public get_table_name(): string;
        public get_table_query(): string;
        public get_tree(): Trellis[];
        public initialize(all): void;
        public load_from_object(source: Ground.ITrellis_Source): void;
        public query_primary_key(): string;
        public sanitize_property(property);
        public set_parent(parent: Trellis): void;
    }
}
declare module Ground {
    interface IService_Response {
        objects: any[];
    }
    interface Query_Filter {
        property: string;
        value;
        operator?: string;
    }
    interface Query_Sort {
        property;
        dir?;
    }
    interface Query_Wrapper {
        start: string;
        end: string;
    }
    interface Property_Query_Source {
        filters?: Query_Filter[];
        sorts?: Query_Sort[];
        expansions?: string[];
        reductions?: string[];
        properties?: Property_Query_Source[];
    }
    interface External_Query_Source extends Property_Query_Source {
        trellis: string;
    }
    interface Internal_Query_Source {
        fields?;
        filters?: any[];
        joins?: string[];
        arguments?;
    }
    class Query {
        public ground: Ground.Core;
        public main_table: string;
        public joins: string[];
        public post_clauses: any[];
        public limit: string;
        public trellis: Ground.Trellis;
        public db: Ground.Database;
        public include_links: boolean;
        public fields: string[];
        public base_path: string;
        public arguments: {};
        public expansions: string[];
        public wrappers: Query_Wrapper[];
        private row_cache;
        public type: string;
        public properties;
        public source: External_Query_Source;
        public filters: string[];
        public run_stack;
        public property_filters: Query_Filter[];
        static operators: string[];
        public each;
        private links;
        constructor(trellis: Ground.Trellis, base_path?: string);
        public add_arguments(args): void;
        public add_filter(clause: string, arguments?: any[]): void;
        public add_property_filter(property: string, value?, operator?: string): void;
        public add_key_filter(value): void;
        public add_field(clause: string, arguments?): void;
        public add_join(clause: string, arguments?): void;
        public add_post(clause: string, arguments?): void;
        public add_expansion(clause): void;
        public add_link(property): void;
        public add_sort(sort: Query_Sort): string;
        public add_wrapper(wrapper: Query_Wrapper): void;
        public generate_pager(offset?: number, limit?: number): string;
        public generate_sql(properties): string;
        public get_fields_and_joins(properties: {
            [name: string]: Ground.Property;
        }, include_primary_key?: boolean): Internal_Query_Source;
        public get_primary_key_value();
        static generate_property_join(property: Ground.Property, seeds): string;
        public create_sub_query(trellis: Ground.Trellis, property: Ground.Property): Query;
        public get_many_list(seed, property: Ground.Property, relationship: Ground.Relationships): Promise;
        public get_path(...args: string[]): string;
        public get_reference_object(row, property: Ground.Property): Promise;
        public has_expansion(path: string): boolean;
        public process_row(row): Promise;
        public query_link_property(seed, property): Promise;
        public process_property_filter(filter): Internal_Query_Source;
        public process_property_filters(): Internal_Query_Source;
        public extend(source: External_Query_Source): void;
        public run_core(): Promise;
        public run(): Promise;
        public run_single(): Promise;
        static get_identity_sql(property: Ground.Property, cross_property?: Ground.Property): string;
        static generate_join(property: Ground.Property, cross_property?: Ground.Property): string;
        static query_path(path: string, args: any[], ground: Ground.Core): Promise;
        static follow_path(path, args: any[], ground: Ground.Core): string;
        private static process_tokens(tokens, args, ground);
    }
}
declare var uuid;
declare module Ground {
    interface IUser {
        id;
    }
    class Update implements Ground.IUpdate {
        public seed: Ground.ISeed;
        private fields;
        public override: boolean;
        public trellis: Ground.Trellis;
        public main_table: string;
        public ground: Ground.Core;
        public db: Ground.Database;
        public user: IUser;
        public log_queries: boolean;
        public run_stack;
        constructor(trellis: Ground.Trellis, seed: Ground.ISeed, ground?: Ground.Core);
        public get_access_name(): string;
        private generate_sql(trellis);
        private update_embedded_seed(property, value);
        private create_record(trellis);
        private update_record(trellis, id, key_condition);
        private apply_insert(property, value);
        public is_create_property(property: Ground.Property): boolean;
        private get_field_value(property, seed);
        private is_update_property(property);
        private update_links(trellis, id, create?);
        private update_many_to_many(property, create?);
        private update_one_to_many(property);
        private update_reference(property, id);
        private update_reference_object(other, property);
        public run(): Promise;
    }
}
declare module Ground {
    class Delete implements Ground.IUpdate {
        public trellis: Ground.Trellis;
        public seed: Ground.ISeed;
        constructor(trellis: Ground.Trellis, seed: Ground.ISeed);
        public get_access_name(): string;
        public run(): Promise;
    }
}
declare module Ground {
    interface IProperty_Source {
        name?: string;
        type: string;
        insert?: string;
        is_virtual?: boolean;
        is_readonly?: boolean;
        is_private?: boolean;
        property?: string;
        trellis?: string;
    }
    interface ITrellis_Source {
        plural: string;
        parent: string;
        name: string;
        primary_key: string;
        properties: IProperty_Source[];
        is_virtual: boolean;
    }
    interface ISeed {
        _deleted?;
    }
    interface IUpdate {
        run: () => Promise;
        get_access_name(): string;
    }
    function path_to_array(path);
    class Property_Type {
        public name: string;
        public property_class;
        public field_type;
        public default_value;
        public parent: Property_Type;
        public db: Ground.Database;
        constructor(name: string, info, types: Property_Type[]);
        public get_field_type();
    }
    class Core extends MetaHub.Meta_Object {
        public trellises: Ground.Trellis[];
        public tables: Ground.Table[];
        public views: any[];
        public property_types: Property_Type[];
        public db: Ground.Database;
        public log_queries: boolean;
        public log_updates: boolean;
        constructor(config, db_name: string);
        public add_trellis(name: string, source: ITrellis_Source, initialize_parent?: boolean): Ground.Trellis;
        public get_base_property_type(type);
        public convert_value(value, type);
        public create_query(trellis_name: string, base_path?: string): Ground.Query;
        public create_update(trellis, seed?: ISeed, user?: Ground.IUser): IUpdate;
        public delete_object(trellis: Ground.Trellis, seed: ISeed): Promise;
        public initialize_trellises(subset: Ground.Trellis[], all?): void;
        public insert_object(trellis, seed?: ISeed, user?: Ground.IUser, as_service?: boolean): Promise;
        static is_private(property: Ground.Property): boolean;
        static is_private_or_readonly(property: Ground.Property): boolean;
        public update_object(trellis, seed?: ISeed, user?: Ground.IUser, as_service?: boolean): Promise;
        static load_json_from_file(filename: string);
        public load_property_types(filename: string): void;
        public load_schema_from_file(filename: string): void;
        public load_tables(tables: any[]): void;
        public load_trellises(trellises: ITrellis_Source[]): Ground.Trellis[];
        private parse_schema(data);
        static remove_fields(object, trellis: Ground.Trellis, filter);
        public sanitize_trellis_argument(trellis): Ground.Trellis;
        static to_bool(input): boolean;
    }
}
declare module Ground {
    interface IField {
        relationship: string;
        name: string;
        share: string;
    }
    class Table {
        public name: string;
        public properties: {};
        public indexes: any[];
        public ground: Ground.Core;
        public db_name: string;
        public trellis: Ground.Trellis;
        public primary_keys: any[];
        public query: string;
        constructor(name: string, ground: Ground.Core);
        public connect_trellis(trellis: Ground.Trellis): void;
        static create_from_trellis(trellis: Ground.Trellis, ground?: Ground.Core): Table;
        public create_sql(ground: Ground.Core): string;
        static create_sql_from_array(table_name: string, source: any[], primary_keys?: any[], indexes?: any[]): string;
        public create_sql_from_trellis(trellis: Ground.Trellis): string;
        private get_primary_keys(trellis);
        static format_value(value);
        static generate_index_sql(name: string, index): string;
        public load_from_schema(source): void;
    }
}
declare module Ground {
    interface Identity {
        name: string;
        trellis: Ground.Trellis;
        keys: Identity_Key[];
    }
    interface Identity_Key {
        name: string;
        type: string;
        property: Ground.Property;
    }
    class Link_Trellis implements Ground.ITrellis {
        public properties;
        public seed;
        public table_name: string;
        public trellises: Ground.Trellis[];
        public trellis_dictionary: {};
        public identities: Identity[];
        constructor(trellises: Ground.Trellis[]);
        public create_identity(trellis: Ground.Trellis): Identity;
        static create_from_property(property: Ground.Property): Link_Trellis;
        static create_reference(property: Ground.Property, name: string): Identity_Key;
        public generate_join(seeds: {}): string;
        public generate_delete_row(seeds: any[]): string;
        public generate_insert(seeds): string;
        private generate_table_name();
        public get_key_condition(key: Identity_Key, seed, fill_blanks?: boolean): string;
        public get_condition_string(seeds): string;
        public get_identity_conditions(identity: Identity, seed, fill_blanks?: boolean): any[];
        public get_conditions(seeds): string[];
        public get_identity_by_trellis(trellis: Ground.Trellis): Identity;
    }
}
declare module Ground {
    enum Relationships {
        none,
        one_to_one,
        one_to_many,
        many_to_many,
    }
    class Property {
        public name: string;
        public parent: Ground.Trellis;
        public type: string;
        public is_readonly: boolean;
        public insert: string;
        public other_property: string;
        public default;
        public other_trellis: Ground.Trellis;
        public other_trellis_name: string;
        public is_private: boolean;
        public is_virtual: boolean;
        public is_composite_sub: boolean;
        public composite_properties: any[];
        constructor(name: string, source: Ground.IProperty_Source, trellis: Ground.Trellis);
        public initialize_composite_reference(other_trellis: Ground.Trellis): void;
        public get_data(): Ground.IProperty_Source;
        public get_default(): any;
        public get_field_name(): string;
        public get_field_override(create_if_missing?: boolean): Ground.IField;
        public get_field_type();
        public get_seed_name(): string;
        public get_sql_value(value, type?);
        public get_other_id(entity);
        public get_other_property(create_if_none?: boolean): Property;
        public get_property_type(): Ground.Property_Type;
        public get_referenced_trellis(): Ground.Trellis;
        public get_relationship(): Relationships;
        public get_field_query(): string;
        public query(): string;
    }
}
declare module "ground" {
  export = Ground
}