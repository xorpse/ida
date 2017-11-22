(** An IDA context *)
type t

(** Type of script to run *)
type script_type = [ `Idc | `Python ]

(** Create a context to interact with an IDA instance at [path] *)
val create             : path:string -> t option

(** Run a given script using IDA; return value indicates success/failure *)
val run                : ?script_type:script_type -> ?remove_database:bool -> t:t -> script:string -> string -> bool

(** Return the expected database extension of the IDA context based upon the
    IDA executable name
  *)
val database_extension : t:t -> string
