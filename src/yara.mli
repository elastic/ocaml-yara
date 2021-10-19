(** {1 Yara! In OCaml!} *)

type error = [ `Yara of int ]
type 'ok result = ('ok, error) Stdlib.result

exception Yara_error of int

(** {2 Library initialization and cleanup} *)

val init_dynamic : ?lib:Dl.library -> unit -> unit
(** [init_dynamic ?lib ()] loads the libyara dynamic library *)

val initialize : unit -> unit result

val initialize_exn : unit -> unit
(** [initialize ()] must be called from the main thread before the library can
    be used.

    @raise Yara_error
      if using [initialize_exn] and libyara has a problem during initialization. *)

val finalize : unit -> unit result

val finalize_exn : unit -> unit
(** [finalize ()] must be called from the main thread once the library is no
    longer in use.

    @raise Yara_error
      if using [finalize_exn] and libyara has a problem during finalization. *)

(** {3 Error handling} *)

val open_error : 'ok result -> ('ok, [> error ]) Stdlib.result
val pp_error : Format.formatter -> error -> unit
val error_to_msg : 'ok result -> ('ok, [ `Msg of string ]) Stdlib.result

module Rule : sig
  (** {1 Individual yara rules, from a match} *)

  type metadata =
    | Int of int64
    | Bool of bool
    | String of string

  type t
  (** A single rule *)

  val get_identifier : t -> string
  (** [get_identifier rule] returns the identifier associated with [rule] if it
      has one *)

  val get_namespace : t -> string
  (** [get_namespace rule] returns the namespace associated with [rule] if it
      has one *)

  val get_metadata : t -> (string * metadata) list
end

module Rules : sig
  (** {1 Compiled yara rules} *)

  type t
  (** A set of compiled rules *)

  (** The different possible messages that can be sent to a callback when a rule
      is checked *)
  type message =
    | Rule_matching of Rule.t
    | Rule_not_matching of Rule.t
    | Scan_finished
    | Import_module
    | Module_imported  (**  *)

  type callback_result =
    [ `Abort
    | `Continue
    | `Error
    ]
  (** Possible return values from a callback *)

  exception Unable_to_allocate_rules

  (** Possible errors when performing a scan *)
  type scan_error =
    | Insufficient_memory
    | Too_many_scan_threads
    | Scan_timeout
    | Callback_error
    | Too_many_matches  (**  *)

  type error = [ `Yara_rules of scan_error ]
  type 'ok result = ('ok, error) Stdlib.result

  exception Scan_error of scan_error

  val scan :
    ?flags:'a ->
    ?timeout:int ->
    (message -> callback_result) ->
    t ->
    string ->
    unit result
  (** [scan ?flags ?timeout callback rules bytes] checks [rules] against
      [bytes], calling [callback] each time there is an event.

      @param timeout specifies a maximum length of time to spend scanning *)

  val scan_exn :
    ?flags:'a ->
    ?timeout:int ->
    (message -> callback_result) ->
    t ->
    string ->
    unit
  (** Like {!scan} except that it raises if there is an error during scanning.

      @raise Scan_error if there is an error scanning the sample *)

  val scan_names :
    ?flags:'a ->
    ?timeout:int ->
    t ->
    string ->
    ([ `Matches of string list ] * [ `Misses of string list ]) result
  (** [scan_names ?flags ?timeout t bytes] returns the names of rules that match
      or miss from [t] against [bytes]. *)

  val scan_names_exn :
    ?flags:'a ->
    ?timeout:int ->
    t ->
    string ->
    [ `Matches of string list ] * [ `Misses of string list ]
  (** Like {!scan_names_exn} except that it raises if there is an error during
      scanning.

      @raise Scan_error if there is an error scanning the sample *)

  val scan_rules :
    ?flags:'a ->
    ?timeout:int ->
    t ->
    string ->
    ([ `Matches of Rule.t list ] * [ `Misses of Rule.t list ]) result
  (** [scan_rules ?flags ?timeout t bytes] returns the rules that match or miss
      [t] against [bytes]. *)

  val scan_rules_exn :
    ?flags:'a ->
    ?timeout:int ->
    t ->
    string ->
    [ `Matches of Rule.t list ] * [ `Misses of Rule.t list ]
  (** Like {!scan_rules_exn} except that it raises if there is an error during
      scanning.

      @raise Scan_error if there is an error scanning the sample *)

  (** {3 Generic error handling} *)

  val open_error : 'a result -> ('a, [> error ]) Stdlib.result
  val pp_error : Format.formatter -> error -> unit
  val error_to_msg : 'a result -> ('a, [ `Msg of string ]) Stdlib.result
end

module Compiler : sig
  (** {2 Rule compilers} *)

  type t
  (** A rule compiler *)

  type error = [ `Yara_compiler of int ]
  type 'ok result = ('ok, error) Stdlib.result

  exception Unable_to_allocate_compiler

  val make : unit -> t
  (** [make ()] creates a new rule compiler

      @raise Unable_to_allocate_compiler if allocation fails *)

  val add_string : ?namespace:string -> t -> string -> unit result
  (** [add_string ?namespace compiler s] adds [s] to [compiler]

      @return Error if [s] doesn't compile cleanly *)

  val add_string_exn : ?namespace:string -> t -> string -> unit
  (** Like {!add_string} but raises if the rule does not compile cleanly

      @raise Invalid_argument if the rule doesn't compile cleanly *)

  val get_rules : t -> Rules.t

  (** {3 Generic error handling} *)

  val open_error : 'a result -> ('a, [> error ]) Stdlib.result
  val pp_error : Format.formatter -> error -> unit
  val error_to_msg : 'a result -> ('a, [ `Msg of string ]) Stdlib.result
end

val to_rules : string list -> Rules.t Compiler.result
(** [to_rules s] returns the rules associated with [s] *)

val to_rules_exn : string list -> Rules.t
(** Like {!to_rules} except that it raises if the rules do not compile cleanly.

    @raise Invalid_argument if the rule doesn't compile cleanly *)
